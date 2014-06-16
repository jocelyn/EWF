note
	description: "Handles users and corresponding digest infos, such as nonces, nonce counts etc."
	author: "Damian"
	date: "June 6, 2014"
	revision: "$Revision$"

class
	NONCE_MANAGER

create
	make

feature -- initialization

	make
		do
			create nonces.make (0)
			create nonce_count.make (0)
		end

feature -- access

	-- For username (key), stores list of nonces (value).
	nonces: STRING_TABLE[ARRAYED_LIST[STRING]]

	-- For username (key), stores nonce-count (value).
	nonce_count: STRING_TABLE[STRING]


end
