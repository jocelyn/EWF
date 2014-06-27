note
	description: "[
			Objects that manager nonce and users in memory
		]"
	author: "$Author$"
	date: "$Date$"
	revision: "$Revision$"

class
	MEMORY_USER_AND_NONCE_MANAGER

inherit
	NONCE_AND_USER_MANAGER

	MEMORY_NONCE_MANAGER
		rename
			make as make_nonce_manager
		end

	MEMORY_USER_MANAGER
		rename
			make as make_user_manager
		end

create
	make

feature {NONE} -- initialization

	make (a_ttl: INTEGER)
			-- Set `time_to_live' for nonces to `a_ttl'.
		do
			make_nonce_manager (a_ttl)
			make_user_manager
		ensure
			ttl_set: time_to_live = a_ttl
		end

end
