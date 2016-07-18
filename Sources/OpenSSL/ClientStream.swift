// SSLClientStream.swift
//
// The MIT License (MIT)
//
// Copyright (c) 2015 Zewo
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDINbG BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import COpenSSL
import Foundation

public final class SSLClientStream: Stream {
	private let context: SSLClientContext
	private let rawStream: Stream
	private let ssl: Session
	private let readIO: IO
	private let writeIO: IO

	public var closed: Bool = false

	public init(context: SSLClientContext, rawStream: Stream, SNIHostname: String? = nil) throws {
		OpenSSL.initialize()

		self.context = context
		self.rawStream = rawStream

		readIO = try IO(method: .Memory)
		writeIO = try IO(method: .Memory)

		ssl = try Session(context: context)
		ssl.setIO(readIO: readIO, writeIO: writeIO)

		if let hostname = SNIHostname {
			try ssl.setServerNameIndication(hostname: hostname)
		}

		ssl.setConnectState()
	}
    
    public func receive(upTo byteCount: Int, timingOut deadline: Double) throws -> Data {
        var decryptedData = Data()
        
        while true {
            do {
                decryptedData += try ssl.read(upTo:byteCount)
                if decryptedData.count > 0 {
                    return decryptedData
                }
            } catch Session.Error.WantRead {
                if decryptedData.count > 0 {
                    return decryptedData
                }
                
                do {
                    let data = try rawStream.receive(upTo:DEFAULT_BUFFER_SIZE, timingOut: deadline)
                    try readIO.write(data)
                } catch StreamError.closedStream(let _data) {
                    return decryptedData + _data
                }
            } catch Session.Error.ZeroReturn {
                return decryptedData
            }
        }
    }

	public func send(_ data: Data, timingOut deadline: Double) throws {
		loop: while !ssl.initializationFinished {
			do {
				try ssl.handshake()
			} catch Session.Error.WantRead {}
			do {
				try send()
			} catch IO.Error.ShouldRetry {
				if ssl.initializationFinished {
					break loop
				}
			}
			try rawStream.flush()
			let data = try rawStream.receive(upTo: 16384, timingOut: deadline)
			try readIO.write(data)
		}

		if data.count > 0 {
			ssl.write(data)
			do {
				try send()
			} catch IO.Error.ShouldRetry {}
		} else {
			try rawStream.send(data)
		}
	}

	public func flush(timingOut deadline: Double) throws {
		try rawStream.flush()
	}

	public func close() throws {
		try rawStream.close()
	}

	private func send() throws {
		let data = try writeIO.read()
		try rawStream.send(data)
	}
}
