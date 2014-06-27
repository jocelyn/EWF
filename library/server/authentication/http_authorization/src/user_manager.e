note
	description: "Handles users, for digest and basic authentication"
	author: "Damian"
	date: "June 6, 2014"
	revision: "$Revision$"

deferred class
	USER_MANAGER

feature -- access

	password (a_user: STRING): detachable STRING
			-- Returns password associated with `a_user', or Void, if `a_user' is unknown.
		deferred
		end

feature -- status report

	user_exists (a_user: STRING): BOOLEAN
			-- Is username `a_user' known?
		deferred
		ensure
				-- TODO Is there something like "if and only if"?
			result_correct: (Result implies password (a_user) /= Void) and (not Result implies password (a_user) = Void)
		end

end
