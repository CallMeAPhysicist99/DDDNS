// Hyperswarm sidecar: handles discovery, NAT traversal and encryption.
// Talks to the parent process with newline-delimited JSON over stdin/stdout.
// Logs go to stderr so they never corrupt the stdout protocol.
//
// The first command must be "init" with the node's seed; the seed is passed
// over stdin (not argv) so it doesn't show up in the process list.
//
// Commands (stdin):
//   {"cmd":"init","seed":"<64 hex>"}       create the node, replies "ready"
//   {"cmd":"join","topic":"<topic>"}        announce + look up peers on a topic
//   {"cmd":"leave","topic":"<topic>"}
//   {"cmd":"send","peer":"<hex>","data":<any JSON>}
//   {"cmd":"broadcast","data":<any JSON>}
//   {"cmd":"firewall","allow":["<hex>",...] | null,"deny":["<hex>",...]}
//                                           allow null = everyone; deny always wins
//   {"cmd":"disconnect","peer":"<hex>"}
//   {"cmd":"goodbye","topic":"<topic>","data":<any JSON>}
//                                           leave topic, send data to every peer, close them all
//   {"cmd":"peers"}
//   {"cmd":"sign","id":<n>,"data":"<string>"}                 -> signed (id, signature)
//   {"cmd":"verify","id":<n>,"data":"<string>","signature":"<hex>","publicKey":"<hex>"}
//                                                            -> verified (id, ok)
//   {"cmd":"shutdown"}
//
// Events (stdout):
//   ready (publicKey), joined, left, peer_connected (peer, ip, port),
//   peer_disconnected, message, peers, goodbye_sent, signed, verified,
//   public_ip (ip, firewalled): this node's public IP and whether inbound connections
//             are blocked; sent when first known and whenever either changes,
//   peer_limited (peer, reason, minutes): a peer broke a limit below and was cut off, error
//
// Limits on what a peer may send (anything more and it's cut off, then refused
// for TIMEOUT_MINUTES):
//   MAX_MESSAGE bytes in one message (a full sync is one message)
//   RATE messages per second on average, with bursts of up to BURST

import Hyperswarm from 'hyperswarm'
import DHT from 'hyperdht'
import crypto from 'hypercore-crypto'
import b4a from 'b4a'
import { createHash } from 'node:crypto'
import readline from 'node:readline'
import { StringDecoder } from 'node:string_decoder'

const MAX_MESSAGE = 8 * 1024 * 1024
const RATE = 100
const BURST = 1000
const TIMEOUT_MINUTES = 10

let swarm = null
let keyPair = null
let allow = null // Set of hex public keys, or null to accept everyone
let deny = new Set() // always rejected, even if also in allow
const peers = new Map() // hex public key -> connection
const timeouts = new Map() // hex public key -> time (ms) until which it's refused for breaking a limit

function emit (obj) {
  process.stdout.write(JSON.stringify(obj) + '\n')
}

function log (...args) {
  console.error('[sidecar]', ...args)
}

function topicOf (topic) {
  return createHash('sha256').update('dddns:' + topic).digest()
}

function write (conn, data) {
  conn.write(JSON.stringify(data) + '\n')
}

function init (seedHex) {
  keyPair = DHT.keyPair(b4a.from(seedHex, 'hex'))
  swarm = new Hyperswarm({
    keyPair,
    // Return true to REJECT the connection.
    firewall (remotePublicKey) {
      return !passes(b4a.toString(remotePublicKey, 'hex'))
    }
  })
  swarm.on('connection', onConnection)
  emit({ event: 'ready', publicKey: b4a.toString(keyPair.publicKey, 'hex') })

  // Our public IP as the DHT sees it. Reported when first known and whenever it changes.
  swarm.dht.on('nat-update', checkPublicIp)
  swarm.dht.on('network-change', checkPublicIp)
  setInterval(checkPublicIp, 30000).unref()
}

// firewalled: the DHT couldn't reach this node's UDP port unasked, i.e. it's behind
// a NAT or firewall without a forwarded port. Peers still reach it by hole punching.
let publicIp = null
let firewalled = null
function checkPublicIp () {
  const dht = swarm && swarm.dht
  if (!dht || !dht.host) return
  if (dht.host !== publicIp || dht.firewalled !== firewalled) {
    publicIp = dht.host
    firewalled = dht.firewalled
    emit({ event: 'public_ip', ip: publicIp, firewalled })
  }
}

// May this peer connect? deny always wins; allow null = everyone.
function passes (id) {
  if (deny.has(id) || (timeouts.get(id) || 0) > Date.now()) return false
  return allow === null || allow.has(id)
}

// Hyperswarm bans a peer for good once the firewall rejects it. Lift that ban
// for peers that pass now (unblocked, rejoined, or their timeout ran out).
function unbanPassing () {
  for (const [id, info] of swarm.peers) {
    if (info.banned && passes(id)) {
      info.ban(false)
      info.attempts = 0
    }
  }
}

// A peer broke a limit: drop it and refuse it for a while.
function cutOff (id, conn, reason) {
  if (timeouts.get(id) > Date.now()) return
  timeouts.set(id, Date.now() + TIMEOUT_MINUTES * 60000)
  conn.destroy()
  log('cut off', id.slice(0, 8) + ':', reason)
  emit({ event: 'peer_limited', peer: id, reason, minutes: TIMEOUT_MINUTES })
  setTimeout(() => {
    timeouts.delete(id)
    if (swarm) unbanPassing()
  }, TIMEOUT_MINUTES * 60000).unref()
}

function onConnection (conn) {
  const id = b4a.toString(conn.remotePublicKey, 'hex')
  peers.set(id, conn)
  // Address of the other end of the UDP stream. If the connection is relayed,
  // this is the relay's address, not the peer's.
  const raw = conn.rawStream || {}
  emit({ event: 'peer_connected', peer: id, ip: raw.remoteHost || null, port: raw.remotePort || null })

  // Peer wire format is also newline-delimited JSON. The decoder keeps a
  // character that's split across two chunks in one piece.
  const decoder = new StringDecoder('utf8')
  let buf = ''
  let tokens = BURST
  let refilled = Date.now()
  conn.on('data', (chunk) => {
    if (timeouts.get(id) > Date.now()) return // cut off; whatever was still on its way is dropped
    buf += decoder.write(chunk)
    if (buf.length > MAX_MESSAGE) return cutOff(id, conn, `sent a message over ${MAX_MESSAGE / 1048576} MB`)
    let i
    while ((i = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, i)
      buf = buf.slice(i + 1)
      if (!line) continue
      const t = Date.now()
      tokens = Math.min(BURST, tokens + (t - refilled) / 1000 * RATE)
      refilled = t
      if (--tokens < 0) return cutOff(id, conn, `sent more than ${RATE} messages a second`)
      try {
        emit({ event: 'message', peer: id, data: JSON.parse(line) })
      } catch {
        log('dropped malformed message from', id.slice(0, 8))
      }
    }
  })

  conn.on('close', () => {
    if (peers.get(id) === conn) {
      peers.delete(id)
      emit({ event: 'peer_disconnected', peer: id })
    }
  })
  conn.on('error', (err) => log('connection error', id.slice(0, 8), err.message))
}

async function handle (msg) {
  if (msg.cmd === 'init') {
    if (swarm) return emit({ event: 'error', message: 'already initialised' })
    return init(msg.seed)
  }
  if (msg.cmd === 'shutdown') return shutdown()
  if (!swarm) return emit({ event: 'error', message: 'send init first' })

  switch (msg.cmd) {
    case 'join': {
      const discovery = swarm.join(topicOf(msg.topic), { server: true, client: true })
      await discovery.flushed()
      emit({ event: 'joined', topic: msg.topic })
      checkPublicIp() // announcing usually teaches the DHT our public address
      // Hyperswarm only looks for new peers every ~10 minutes. Nodes that joined
      // at the same moment as us weren't announced yet, so look again shortly.
      for (const delay of [5000, 20000, 60000]) {
        setTimeout(() => discovery.refresh().catch(() => {}), delay).unref()
      }
      break
    }
    case 'leave':
      await swarm.leave(topicOf(msg.topic))
      emit({ event: 'left', topic: msg.topic })
      break
    case 'send': {
      const conn = peers.get(msg.peer)
      if (!conn) return emit({ event: 'error', message: 'not connected to peer ' + msg.peer })
      write(conn, msg.data)
      break
    }
    case 'broadcast':
      for (const conn of peers.values()) write(conn, msg.data)
      break
    case 'firewall': {
      allow = msg.allow == null ? null : new Set(msg.allow)
      deny = new Set(msg.deny || [])
      // The firewall only screens new connections; drop existing ones that no longer pass.
      // end() flushes queued messages first (e.g. the admin change that caused the drop).
      for (const [id, conn] of peers) {
        if (!passes(id)) {
          conn.end()
          setTimeout(() => conn.destroy(), 3000).unref()
        }
      }
      unbanPassing()
      break
    }
    case 'disconnect': {
      const conn = peers.get(msg.peer)
      if (conn) conn.destroy()
      break
    }
    case 'goodbye': {
      // Leave first so discovery doesn't reconnect us while we say goodbye.
      if (msg.topic) await swarm.leave(topicOf(msg.topic))
      const closing = [...peers.values()].map((conn) => new Promise((resolve) => {
        conn.once('close', resolve)
        write(conn, msg.data)
        conn.end() // flushes the goodbye before closing
      }))
      // Don't wait forever on a peer that never acknowledges the close.
      await Promise.race([Promise.all(closing), new Promise((resolve) => setTimeout(resolve, 3000))])
      emit({ event: 'goodbye_sent' })
      break
    }
    case 'peers':
      emit({ event: 'peers', peers: [...peers.keys()] })
      break
    case 'sign': {
      const signature = crypto.sign(b4a.from(msg.data), keyPair.secretKey)
      emit({ event: 'signed', id: msg.id, signature: b4a.toString(signature, 'hex') })
      break
    }
    case 'verify': {
      let ok = false
      try {
        ok = crypto.verify(b4a.from(msg.data), b4a.from(msg.signature, 'hex'), b4a.from(msg.publicKey, 'hex'))
      } catch {}
      emit({ event: 'verified', id: msg.id, ok })
      break
    }
    default:
      emit({ event: 'error', message: 'unknown command ' + msg.cmd })
  }
}

let closing = false
async function shutdown () {
  if (closing) return
  closing = true
  if (swarm) await swarm.destroy()
  process.exit(0)
}

// If the Python side is gone, writing to it fails (EPIPE): just exit quietly.
process.stdout.on('error', () => process.exit(0))

const rl = readline.createInterface({ input: process.stdin })
rl.on('line', (line) => {
  if (!line.trim()) return
  let msg
  try {
    msg = JSON.parse(line)
  } catch {
    return emit({ event: 'error', message: 'invalid JSON command' })
  }
  handle(msg).catch((err) => emit({ event: 'error', message: err.message }))
})
// Parent died or closed the pipe -> exit too.
rl.on('close', shutdown)
