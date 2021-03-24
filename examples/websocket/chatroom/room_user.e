note
	description: "Summary description for {USER_ROOM}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	ROOM_USER

create
	make, make_with_name,
	make_from_separate

feature {NONE} -- Initialization

	make (ws: WEB_SOCKET)
		do
			create websocket_writer.make_from_websocket (ws)
			id := {UUID_GENERATOR}.generate_uuid.out
		end

	make_with_name (ws: WEB_SOCKET; a_name: READABLE_STRING_GENERAL)
		do
			make (ws)
			create name.make_from_string_general (a_name)
		end

	make_from_separate (u: separate ROOM_USER)
		do
			create id.make_from_separate (u.id)
			if attached u.name as n then
				create name.make_from_separate (N)
			end
			create websocket_writer.make_from_separate_writer (u.websocket_writer)
		end

feature -- Access

	id: IMMUTABLE_STRING_8

	name: detachable IMMUTABLE_STRING_32

	name_or_id: READABLE_STRING_32
		do
			Result := name
			if Result = Void then
				Result := id.to_string_32
			end
		end

	utf_8_name_or_id: READABLE_STRING_8
		do
			Result := {UTF_CONVERTER}.utf_32_string_to_utf_8_string_8 (name_or_id)
		end

	websocket_writer: SHADOW_WEB_SOCKET_WRITER

feature -- Status report	

	same_name (n: READABLE_STRING_GENERAL): BOOLEAN
		do
			Result := attached name as l_name and then n.is_case_insensitive_equal (l_name)
		end

feature -- Element change

	set_name (a_name: READABLE_STRING_GENERAL)
		do
			create name.make_from_string_general (a_name)
		end

	remove_name
		do
			name := Void
		end

feature -- Operation

	disconnect
		do
			websocket_writer.socket.close
		end

	send_text (m: separate READABLE_STRING_GENERAL)
		local
			mesg: STRING_32
		do
			create mesg.make_from_separate (m)
			websocket_writer.send_text ({UTF_CONVERTER}.utf_32_string_to_utf_8_string_8 (mesg))
		end

end
