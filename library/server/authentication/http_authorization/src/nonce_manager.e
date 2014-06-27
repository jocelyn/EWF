note
	description: "Handles nonces related data."

deferred class
	NONCE_MANAGER

feature {NONE} -- data

	time_to_live: INTEGER
			-- Time to live for a nonce, in seconds.
		deferred
		ensure
			Result >= 0
		end

feature -- Access

	nonce_count (a_nonce: STRING): INTEGER
			-- Returns nonce-count associated with `a_nonce', or zero, if `a_nonce' is unknown.
		deferred
		ensure
			nc_non_negative: Result >= 0
			unknown: not nonce_exists (a_nonce) implies Result = 0
		end

feature -- Change

	set_nonce_count (a_nonce: STRING; a_nonce_count: INTEGER)
			-- Set nonce-count associated with `a_nonce' to `a_nonce_count'.
		require
			nonce_exists (a_nonce)
			nc_smaller: nonce_count (a_nonce) < a_nonce_count
		deferred
		ensure
			set: nonce_count (a_nonce) = a_nonce_count
		end

feature -- status report

	nonce_exists (a_nonce: STRING): BOOLEAN
			-- Is nonce `a_nonce' known?
		deferred
		end

	is_nonce_stale (a_nonce: STRING): BOOLEAN
			-- Returns true, if nonce has expired, i.e., is older than `time_to_live'.
		require
			nonce_known: nonce_exists (a_nonce)
		deferred
		end

end
