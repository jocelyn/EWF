note
	description: "Summary description for {MESSAGE_ROOM}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	ROOM

create
	make

feature

	make (a_capacity: INTEGER)
		do
			create users.make (a_capacity)

		end

feature -- Access

	users: STRING_TABLE [ROOM_USER]

	count: INTEGER
		do
			Result := users.count
		end

feature -- Element change

	register_user (u: separate ROOM_USER)
		local
			loc_user: ROOM_USER
		do
			create loc_user.make_from_separate (u)
			loc_user.send_text ({STRING_32} "Welcome user " + loc_user.name_or_id)
			send_message_to_others ({STRING_32} "User [" + loc_user.name_or_id + {STRING_32} "] entered the room.", loc_user)
			users[loc_user.id] := loc_user
		end

	update_user_name (uid: separate READABLE_STRING_8; uname: detachable separate READABLE_STRING_GENERAL)
		local
			l_uid: STRING_8
			n: STRING_32
			l_old: READABLE_STRING_32
		do
			create l_uid.make_from_separate (uid)
			if attached users [l_uid] as loc_user then
				l_old := loc_user.name_or_id
				if uname = Void then
					loc_user.remove_name
				else
					create n.make_from_separate (uname)
					loc_user.set_name (n)
				end
				send_message_to_all ({STRING_32} "User changed his name from @" + l_old + " to @" + loc_user.name_or_id)
			end
		end

	unregister_user (uid: separate READABLE_STRING_8)
		local
			l_uid: STRING_8
		do
			create l_uid.make_from_separate (uid)
			if attached users [l_uid] as loc_user then
				send_message_to_all ({STRING_32} "User [" + loc_user.name_or_id + "] left")
				users.remove (loc_user.id)
				loc_user.disconnect
			else
				send_message_to_all ("User [" + l_uid + "] left")
			end
		end

feature -- Operation

	send_new_user_message (a_uid: separate READABLE_STRING_8)
		local
			l_uid: STRING_8
		do
			create l_uid.make_from_separate (a_uid)
			across
				users as ic
			loop
--				separate ic.item as u do
				if attached ic.item as u then
					u.send_text ("New user [" + l_uid + "]")
				end
			end
		end

	send_message_to (msg: separate READABLE_STRING_GENERAL; a_user_names: separate ITERABLE [READABLE_STRING_GENERAL])
		local
			m: STRING_32
			lst: ARRAYED_LIST [STRING_32]
		do
			create lst.make (1)
			across
				a_user_names as ic
			loop
				lst.force (create {STRING_32}.make_from_separate (ic.item))
			end

			create m.make_from_separate (msg)
			across
				users as ic
			loop
				if attached ic.item as u then
					if across lst as to_ic some u.same_name (to_ic.item) end then
						u.send_text (m)
					end
				end
			end
		end

	send_message_to_others (msg: separate READABLE_STRING_GENERAL; a_user: separate ROOM_USER)
		local
			m: STRING_32
			l_uid: STRING_8
		do
			create m.make_from_separate (msg)
			create l_uid.make_from_separate (a_user.id)
			across
				users as ic
			loop
				if attached ic.item as u then
					if not u.id.same_string (l_uid) then
						u.send_text (m)
					end
				end
			end
		end

	send_message_to_all (msg: separate READABLE_STRING_GENERAL)
		local
			m: STRING_32
		do
			create m.make_from_separate (msg)
			across
				users as ic
			loop
				if attached ic.item as u then
					u.send_text (m)
				end
			end
		end

end
