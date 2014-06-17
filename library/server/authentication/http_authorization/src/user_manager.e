note
	description: "Handles users, for digest and basic authentication"
	author: "Damian"
	date: "June 6, 2014"
	revision: "$Revision$"

class
	USER_MANAGER

create
	make

feature -- initialization

	make(a_ttl: INTEGER)
			-- Set `time_to_live' for nonces to `a_ttl'.
		do
			time_to_live := a_ttl
			create nonce_count_table.make (0)
			create password_table.make (0)
		ensure
			ttl_set: time_to_live = a_ttl
		end

feature -- data

		-- TODO Export to NONE

	nonce_count_table: STRING_TABLE [INTEGER]
		-- For nonce (key), stores current, last seen nonce-count (value).

	password_table: STRING_TABLE [STRING]
		-- For username (key), stores current password (value).

	time_to_live: INTEGER
		-- Time to live for a nonce, in seconds

feature {NONE} -- nonce creation

	new_nonce_value: STRING_8
			-- Create a fresh nonce in the following format:
			--		Base64(timeStamp : MD5(timeStamp : privateKey))
			-- TODO Create nonce according to suggestion in RFC 2617
		local
			date_time: DATE_TIME
			http_time: HTTP_DATE
			base64_encoder: BASE64
			hash: MD5
			l_priv_key: INTEGER
		do
			create base64_encoder
			create hash.make
			create date_time.make_now_utc
			create http_time.make_from_date_time (date_time)

			l_priv_key := private_key

				-- Compute nonce.
			hash.update_from_string (http_time.string + ":" + l_priv_key.out)
			Result := hash.digest_as_string
			Result.to_lower
			Result.prepend (http_time.string + ":")

			Result := base64_encoder.encoded_string (Result)

			debug("user-manager")
				io.put_string ("Nonce before encoding: " + Result + "%N")
			end
		end

feature -- element change

	put_credentials (a_user: STRING; a_password: STRING)
			-- Add new `a_user' with corresponding `a_password'.
		require
			user_unknown: not user_exists (a_user)
		do
			set_password (a_user, a_password)
		ensure
			user_known: user_exists (a_user)
		end


	new_nonce: STRING
			-- Creates a fresh nonce and stores it into `nonce_count_table', with a nonce-count value of 1.
			-- Returns the nonce.
		local
			l_nonce: STRING
		do
			l_nonce := new_nonce_value;

			nonce_count_table.force (0, l_nonce)

			Result := l_nonce
		ensure
			not_empty: not Result.is_empty
		end

	set_password (a_user: STRING; a_password: STRING)
			-- Set password corresponding to `a_user' to `a_password'.
		do
			password_table.force (a_password, a_user)
		ensure
			user_exists: user_exists (a_user)
			password_set: attached password (a_user)as l_pw and then l_pw.same_string (a_password)
		end

	increment_nonce_count (a_nonce: STRING)
			-- Increment nonce-count associated with `user'.
		require
			nonce_known: nonce_exists (a_nonce)
		local
			l_nc: INTEGER
		do
			l_nc := nonce_count_table.item (a_nonce)


			debug ("user-manager")
				io.putstring ("Old nonce-count: " + l_nc.out + "%N")
			end


			l_nc := l_nc + 1


			debug ("user-manager")
				io.putstring ("New nonce-count: " + l_nc.out + "%N")
			end

			nonce_count_table.force (l_nc, a_nonce)
		ensure
				-- FIXME
--			incremented: (old nonce_count_table).item (a_nonce) = nonce_count_table.item (a_nonce) + 1
		end

feature -- status report

	user_exists (a_user: STRING): BOOLEAN
			-- Is username `a_user' known?
		do
			Result := password_table.has (a_user)
		ensure
				-- TODO Is there something like "if and only if"?
			result_correct: (Result implies password_table.has (a_user)) and (not Result implies not password_table.has (a_user))
		end

	nonce_exists(a_nonce: STRING): BOOLEAN
			-- Is nonce `a_nonce' known?
		do
			Result := nonce_count_table.has (a_nonce)
		ensure
			result_correct: (Result implies nonce_count_table.has (a_nonce)) and (not Result implies not nonce_count_table.has (a_nonce))
		end

	is_nonce_stale(a_nonce: STRING): BOOLEAN
			-- Returns true, if nonce has expired, i.e., is older than `time_to_live'.
		require
			nonce_known: nonce_exists (a_nonce)
		local
			l_http_date: HTTP_DATE
			l_duration: DATE_TIME_DURATION
			age_in_seconds: INTEGER_64
		do
			l_http_date := time_from_nonce (a_nonce)

			l_duration := (create {DATE_TIME}.make_now_utc).relative_duration(l_http_date.date_time)

			age_in_seconds := l_duration.seconds_count

			Result := age_in_seconds > time_to_live

			debug ("user-manager")
				io.putstring ("Age of nonce in seconds: " + age_in_seconds.out + "%N")
				io.putstring ("Nonce stale: " + Result.out + "%N")
			end
		end

feature -- access

	password (a_user: STRING): detachable STRING
			-- Returns password associated with `a_user', or Void, if `a_user' is unknown.
		do
			if attached password_table.item (a_user) as l_pw then
				Result := l_pw
			else
				Result := Void
			end
		ensure
			attachment_correct: (attached Result implies attached password_table.item (a_user)) and (not attached Result implies not attached password_table.item (a_user))
		end

	nonce_count (a_nonce: STRING): INTEGER
			-- Returns nonce-count associated with `a_nonce', or zero, if `a_nonce' is unknown.
		do
			Result := nonce_count_table.item (a_nonce)
		ensure
			nc_non_negative: nonce_count_table.item (a_nonce) >= 0
		end

	time_from_nonce(a_nonce: STRING): HTTP_DATE
			-- Returns time encoded in `a_nonce'.
		require
			nonce_known: nonce_exists(a_nonce)
		local
			l_base_decoder: BASE64
			l_decoded_nonce: STRING
			l_time_string: STRING
			l_index: INTEGER
		do
			create l_base_decoder

			l_decoded_nonce := l_base_decoder.decoded_string (a_nonce)

			l_index := l_decoded_nonce.last_index_of (':', l_decoded_nonce.count)

			l_time_string := l_decoded_nonce.substring (1, l_index - 1)

			create Result.make_from_string (l_time_string)

			check
				prefix_correct: l_decoded_nonce.starts_with (l_time_string)
				result_object: l_time_string.same_string (Result.debug_output)
			end
		end


feature -- private key

	private_key: INTEGER_32
			-- Get or compute the private key of the server
		local
			random_int: RANDOM
			l_seed: INTEGER
			l_time: TIME
		once
			create l_time.make_now

     		l_seed := l_time.hour
      		l_seed := l_seed * 60 + l_time.minute
      		l_seed := l_seed * 60 + l_time.second
      		l_seed := l_seed * 1000 + l_time.milli_second

      		create random_int.set_seed (l_seed)

			random_int.forth

			Result := random_int.item

			debug("user-manager")
				io.put_string ("Private key: " + private_key.out + "%N")
			end
		end


invariant
	-- TODO
end
