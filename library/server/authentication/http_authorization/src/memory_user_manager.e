note
	description: "Handles users, for digest and basic authentication"

class
	MEMORY_USER_MANAGER

inherit
	USER_MANAGER

create
	make

feature {NONE} -- initialization

	make
		do
			create password_table.make (0)
		end

feature {NONE} -- data

	password_table: STRING_TABLE [STRING]
			-- For username (key), stores current password (value).
			-- See section 4.13 of RFC 2617 for information of how to store passwords.

feature -- element change

	put_credentials (a_user: STRING; a_password: STRING)
			-- Add new `a_user' with corresponding `a_password'.
		require
			user_unknown: not user_exists (a_user)
		do
			set_password (a_user, a_password)
		ensure
			set: attached password (a_user) as l_pw and then a_password.same_string_general (a_password)
		end

	set_password (a_user: STRING; a_password: STRING)
			-- Set password corresponding to `a_user' to `a_password'.
		do
			password_table.force (a_password, a_user)
		ensure
			password_set: attached password (a_user) as l_pw and then l_pw.same_string (a_password)
		end

feature -- status report

	user_exists (a_user: STRING): BOOLEAN
			-- Is username `a_user' known?
		do
			Result := password_table.has (a_user)
		end

feature -- access

	password (a_user: STRING): detachable STRING
			-- Password associated with `a_user', or Void, if `a_user' is unknown.
		do
			Result := password_table.item (a_user)
		end

end
