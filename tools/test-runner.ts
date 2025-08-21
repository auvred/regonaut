import * as process from 'node:process'
import * as vm from 'node:vm'
import * as fs from 'node:fs'
import { Buffer } from 'node:buffer'
import * as module from 'node:module'

const NIL_MATCH = '!SPECIAL_NIL_MATCH!'

// Undocumented method
// @ts-expect-error
process.stdin._handle.setBlocking(true)
// @ts-expect-error
process.stdout._handle.setBlocking(true)

let ioBuffer: Buffer | null = null
function preallocIoBuffer(minLength: number) {
  if (ioBuffer == null || ioBuffer.byteLength < minLength) {
    ioBuffer = Buffer.alloc(minLength)
  }
  return ioBuffer
}
let secondaryBuffer: Buffer | null = null
function preallocSecondaryBuffer(minLength: number) {
  if (secondaryBuffer == null || secondaryBuffer.byteLength < minLength) {
    secondaryBuffer = Buffer.alloc(minLength)
  }
  return secondaryBuffer
}

const messageHeaderBuffer = Buffer.alloc(5)

function doCounted(
  total: number,
  step: (remaining: number, offset: number) => number,
) {
  let offset = 0
  while (offset < total) {
    const n = step(total - offset, offset)
    // when pipe is in blocking mode, uv_fs_read returns 0 when EOF (similar to pread(2))
    if (n === 0) {
      return false
    }
    offset += n
  }
  return true
}
function readFromStdin(buf: Buffer, total: number) {
  return doCounted(total, (remaining, offset) =>
    fs.readSync(process.stdin.fd, buf, {
      length: remaining,
      offset,
    }),
  )
}

function receiveMessage() {
  if (!readFromStdin(messageHeaderBuffer, messageHeaderBuffer.length)) {
    return null
  }

  const payloadLen = messageHeaderBuffer.readUInt32LE(0)
  const messageType = messageHeaderBuffer.readUint8(4)
  const buf = preallocIoBuffer(payloadLen)

  if (!readFromStdin(buf, payloadLen)) {
    throw new Error('reading payload from stdin')
  }

  return { messageType, payload: buf.subarray(0, payloadLen) }
}

function sendMessage(messageType: number, payload: Buffer | string) {
  const payloadLen = Buffer.byteLength(payload)
  const messageLen = 5 + payloadLen
  const buf = preallocIoBuffer(messageLen)

  buf.writeUint32LE(payloadLen, 0)
  buf.writeUint8(messageType, 4)
  if (Buffer.isBuffer(payload)) {
    payload.copy(buf, 5, 0, payloadLen)
  } else {
    buf.write(payload, 5, 'utf8')
  }

  if (
    !doCounted(messageLen, (remaining, offset) =>
      fs.writeSync(process.stdout.fd, buf, offset, remaining),
    )
  ) {
    throw new Error('writing message to stdout')
  }
}

const prelude262 = `
RegExp.prototype.exec = function (source) {
  const {
    lastIndex,
    index,
    groups,
    namedGroups,
    indices,
    indicesGroups,
  } = _regexpExec(
    Math.floor(Number(this.lastIndex)),
    this.source,
    this.flags,
    source,
  )
  if (this.flags.includes('g') || this.flags.includes('y')) {
    this.lastIndex = lastIndex
  }
  if (groups == null) {
    return null
  }

  const result = [...groups]

  result.index = index
  result.input = source
  Object.defineProperty(result, 'groups', {
    value: namedGroups == null ? undefined : Object.assign(Object.create(null), namedGroups),
    writable: true,
    enumerable: true,
    configurable: true
  })
  
  if (this.flags.includes('d')) {
    Object.defineProperty(result, 'indices', {
      value: indices == null ? undefined : [...indices.map(e => e == null ? undefined : [...e])],
      writable: true,
      enumerable: true,
      configurable: true
    })
    Object.defineProperty(result.indices, 'groups', {
      value: indicesGroups,
      writable: true,
      enumerable: true,
      configurable: true
    })
  }
  
  return result
}

const origRegExp = RegExp

globalThis.RegExp = function RegExp(pattern, flags) {
  const construct = () => {
    if (new.target) {
      return new origRegExp(pattern, flags)
    }
    return origRegExp(pattern, flags)
  }
  if (typeof pattern !== 'string') {
    return construct()
  }

  let err
  try {
    return construct()
  } catch (e) {
    err = e
  }

  const response = _regexpCompile(
    String(pattern),
    String(flags),
  )

  let actualValid = response === 0

  if (actualValid) {
    print(pattern, flags, 'this RegExp is considered invalid by V8')
    throw new Error('this RegExp is considered invalid by V8')
  }
  throw err
}
`

const MSG_TYPE = {
  TEST262_END: 0,
  TEST262_START: 1,
  TEST262_REGEXP_EXEC: 2,
  TEST262_REGEXP_EXEC_MATCHED: 3,
  TEST262_REGEXP_EXEC_NOT_MATCHED: 4,
  TEST262_REGEXP_COMPILE: 5,
  TEST_REGEXP_EXEC: 6,
  TEST_REGEXP_EXEC_ERROR: 7,
  TEST_REGEXP_EXEC_MATCHED: 8,
  TEST_REGEXP_EXEC_NOT_MATCHED: 9,
  TEST_REGEXP_SYNTAX_ERROR: 10,
}

while (true) {
  const message = receiveMessage()
  if (message == null) {
    break
  }
  const { messageType, payload } = message
  switch (messageType) {
    case MSG_TYPE.TEST262_START: {
      const ctx = vm.createContext({
        setTimeout,
        require: module.createRequire(import.meta.url),
        console,
        performance,
        print(...args: unknown[]) {
          console.error(...args)
        },

        _regexpExec(
          lastIndex: number,
          pattern: string,
          flags: string,
          source: string,
        ) {
          {
            const flagsLen = Buffer.byteLength(flags, 'utf8')
            const patternLen = Buffer.byteLength(pattern, 'utf16le')
            const sourceLen = Buffer.byteLength(source, 'utf16le')
            const bufLen = 4 + 1 + flagsLen + 4 + patternLen + 4 + sourceLen
            const buf = preallocSecondaryBuffer(bufLen)
            let offset = 0
            buf.writeUint32LE(lastIndex, offset)
            buf.writeUint8(flagsLen, (offset += 4))
            buf.write(flags, (offset += 1), 'utf8')
            buf.writeUint32LE(patternLen, (offset += flagsLen))
            buf.write(pattern, (offset += 4), 'utf16le')
            buf.writeUint32LE(sourceLen, (offset += patternLen))
            buf.write(source, (offset += 4), 'utf16le')

            sendMessage(MSG_TYPE.TEST262_REGEXP_EXEC, buf.subarray(0, bufLen))
          }
          const response = receiveMessage()
          if (response == null) {
            throw new Error('reading response for RegExp.exec request')
          }
          const { messageType, payload: buf } = response
          switch (messageType) {
            case MSG_TYPE.TEST262_REGEXP_EXEC_NOT_MATCHED:
              return {
                lastIndex: buf.readUint8(0),
              }
            case MSG_TYPE.TEST262_REGEXP_EXEC_MATCHED: {
              let offset = 0
              const groupsCount = buf.readUint32LE(offset)
              offset += 4
              const indices = []
              const groups = []
              let namedGroups = undefined
              let indicesGroups = undefined
              for (let i = 0; i < groupsCount; i++) {
                const start = buf.readUint32LE(offset)
                const end = buf.readUint32LE((offset += 4))
                offset += 4
                if (start === 0xffffffff) {
                  groups[i] = indices[i] = undefined
                } else {
                  groups[i] = source.slice(...(indices[i] = [start, end]))
                }
              }
              const namedGroupsCount = buf.readUint32LE(offset)
              offset += 4
              if (namedGroupsCount > 0) {
                namedGroups = Object.create(null)
                indicesGroups = Object.create(null)
                for (let i = 0; i < namedGroupsCount; i++) {
                  const name = buf
                    .subarray(
                      offset + 4,
                      (offset += 4 + buf.readUint32LE(offset)),
                    )
                    .toString('utf8')
                  const start = buf.readUint32LE(offset)
                  const end = buf.readUint32LE((offset += 4))
                  offset += 4
                  if (start === 0xffffffff) {
                    namedGroups[name] = indicesGroups[name] = undefined
                  } else {
                    namedGroups[name] = source.slice(
                      ...(indicesGroups[name] = [start, end]),
                    )
                  }
                }
              }
              return {
                indices,
                groups,
                namedGroups,
                indicesGroups,
                // @ts-expect-error
                lastIndex: indices[0][1],
                // @ts-expect-error
                index: indices[0][0],
              }
            }
            default:
              throw new Error(`unknown message: ${messageType}`)
          }
        },
        _regexpCompile(pattern: string, flags: string) {
          const flagsLen = Buffer.byteLength(flags, 'utf8')
          const patternLen = Buffer.byteLength(pattern, 'utf16le')
          const bufLen = 1 + flagsLen + 4 + patternLen
          const buf = preallocSecondaryBuffer(bufLen)
          let offset = 0
          buf.writeUint8(flagsLen, offset)
          buf.write(flags, (offset += 1), 'utf8')
          buf.writeUint32LE(patternLen, (offset += flagsLen))
          buf.write(pattern, (offset += 4), 'utf16le')

          sendMessage(MSG_TYPE.TEST262_REGEXP_COMPILE, buf.subarray(0, bufLen))

          const response = receiveMessage()
          if (response == null) {
            throw new Error('reading response for RegExp compile request')
          }
          return response.payload[0]
        },
      })

      let error = ''
      try {
        vm.runInContext(prelude262 + payload, ctx)
      } catch (e) {
        error =
          String(e) +
          (typeof e === 'object' && e != null && 'stack' in e && e.stack != null
            ? `\n${e.stack}`
            : '')
      }
      sendMessage(MSG_TYPE.TEST262_END, error)
      break
    }
    case MSG_TYPE.TEST_REGEXP_EXEC: {
      const flagsLength = payload.readUint8(0)
      let offset = 1
      const flags = payload
        .subarray(offset, (offset += flagsLength))
        .toString('utf8')
      const pattern = payload
        .subarray(offset + 4, (offset += 4 + payload.readUint32LE(offset)))
        .toString('utf16le')
      const source = payload
        .subarray(offset + 4, (offset += 4 + payload.readUint32LE(offset)))
        .toString('utf16le')

      let regexp
      try {
        regexp = new RegExp(pattern, flags)
      } catch (e) {
        sendMessage(MSG_TYPE.TEST_REGEXP_EXEC_ERROR, String(e))
        break
      }
      const result = regexp.exec(source)
      if (result == null) {
        sendMessage(MSG_TYPE.TEST_REGEXP_EXEC_NOT_MATCHED, '')
        break
      }

      const { groups = {} } = result

      const matches = result.slice(1).map(e => e ?? NIL_MATCH)

      for (const [name, value] of Object.entries(groups)) {
        if (value == null) {
          groups[name] = NIL_MATCH
        }
      }

      const groupsSize =
        4 +
        Object.entries(groups).reduce(
          (acc, [name, value]) =>
            acc +
            4 +
            Buffer.byteLength(name, 'utf8') +
            4 +
            Buffer.byteLength(value, 'utf16le'),
          0,
        )
      const matchesSize =
        4 +
        matches.reduce(
          (acc, match) => acc + 4 + Buffer.byteLength(match, 'utf16le'),
          0,
        )
      const bufSize = groupsSize + matchesSize

      const buf = preallocSecondaryBuffer(bufSize)
      const writeString = (str: string, encoding: BufferEncoding) => {
        const length = Buffer.byteLength(str, encoding)
        buf.writeUint32LE(length, offset)
        buf.write(str, (offset += 4), encoding)
        offset += length
      }

      buf.writeUint32LE(Object.keys(groups).length, (offset = 0))
      offset += 4
      for (const [name, value] of Object.entries(groups)) {
        writeString(name, 'utf8')
        writeString(value, 'utf16le')
      }

      buf.writeUint32LE(matches.length, offset)
      offset += 4
      for (const item of matches) {
        writeString(item, 'utf16le')
      }

      sendMessage(MSG_TYPE.TEST_REGEXP_EXEC_MATCHED, buf.subarray(0, bufSize))
      break
    }
    case MSG_TYPE.TEST_REGEXP_SYNTAX_ERROR: {
      const flagsLength = payload.readUint8(0)
      let offset = 1
      const flags = payload
        .subarray(offset, (offset += flagsLength))
        .toString('utf8')
      const pattern = payload
        .subarray(offset + 4, (offset += 4 + payload.readUint32LE(offset)))
        .toString('utf16le')

      let error = ''
      try {
        new RegExp(pattern, flags)
      } catch (e) {
        error = String(e)
      }
      sendMessage(MSG_TYPE.TEST_REGEXP_SYNTAX_ERROR, error)
      break
    }
  }
}
