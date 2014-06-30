note
	description: "Handles users, for digest and basic authentication"

deferred class
	USER_MANAGER

feature -- access

	password (a_user: STRING): detachable STRING
			-- Ppassword associated with `a_user', or Void, if `a_user' is unknown.
		deferred
		ensure
			voidness: user_exists (a_user) /= (Result = Void)
		end

feature -- status report

	user_exists (a_user: STRING): BOOLEAN
			-- Is username `a_user' known?
		deferred
		ensure
			result_correct: Result = (password (a_user) /= Void)
		end

end
