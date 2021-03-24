note
	description: "Summary description for {WSW}."
	date: "$Date$"
	revision: "$Revision$"

class
	SHADOW_WEB_SOCKET_WRITER

inherit
	WEB_SOCKET_WRITER

create
	make_with_socket,
	make_from_websocket,
	make_from_separate_writer

feature {NONE} -- Initialization

	make_with_socket (s: HTTP_STREAM_SOCKET)
		do
			socket := s
		end

	make_from_websocket (ws: WEB_SOCKET)
		do
			make_with_socket (ws.socket)
		end

	make_from_separate_socket (s: separate HTTP_STREAM_SOCKET)
		do
			create {HTTP_STREAM_SHADOW_SOCKET} socket.make_from_separate (s) -- FIXME !!!
		end

	make_from_separate_websocket (ws: separate WEB_SOCKET)
		do
			make_from_separate_socket (ws.socket)
		end

	make_from_separate_writer (wsw: separate SHADOW_WEB_SOCKET_WRITER)
		do
			make_from_separate_socket (wsw.socket)
		end

feature -- Access

	socket: HTTP_STREAM_SOCKET
			-- Underlying connected socket.

feature {WEB_SOCKET_HANDLER, WEB_SOCKET_WRITER} -- Networking

	socket_put_string (s: READABLE_STRING_8)
		do
			socket.put_string_8_noexception (s)
		end

	socket_was_error: BOOLEAN
		do
			Result := socket.was_error
		end

invariant

end
