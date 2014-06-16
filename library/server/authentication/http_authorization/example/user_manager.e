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

	make(ttl: INTEGER)
		do
			time_to_live := ttl
			create nonce_count.make (0)
			create password.make (0)
		end

feature -- data

		-- TODO Export to NONE

	nonce_count: STRING_TABLE[INTEGER]
		-- For nonce (key), stores current, last seen nonce-count (value).

	password: STRING_TABLE[STRING]
		-- For username (key), stores current password (value).

	time_to_live: INTEGER
		-- Time to live for a nonce, in seconds

feature {NONE} -- nonce creation

	new_nonce_value: STRING_8
			-- Create a fresh nonce in the following format:
			--		Base64(timeStamp : MD5(timeStamp : privateKey))
			-- TODO Create nonce according to suggestion in RFC 2617
		require
			-- FIXME Not required
			private_key_exists: attached private_key
		local
			date_time: DATE_TIME
			http_time: HTTP_DATE
			base64_encoder: BASE64
			hash: MD5
			time_string: STRING_8
			l_priv_key: INTEGER
		do
			create base64_encoder
			create hash.make
			create date_time.make_now_utc
			create http_time.make_from_date_time (date_time)
			time_string := http_time.string

			debug("user-manager")
				io.put_string ("Time: " + time_string + "%N")
			end

			l_priv_key := private_key

			hash.update_from_string (time_string + ":" + l_priv_key.out)
			Result := hash.digest_as_string
			Result.to_lower
			Result.prepend (time_string + ":")

			debug("user-manager")
				io.put_string ("Nonce before encoding: " + Result + "%N")
			end

			Result := base64_encoder.encoded_string (Result)

--			io.put_string ("Nonce: " + Result + "%N")
		end


--		add_nonce_once
--				-- Add one nonce, s.t. we can test the stale field.
--			once
--				io.put_string ("Called add_nonce_once%N")
--				server_nonce_list.force (new_nonce_value)
--		end

feature -- element change

	new_user(a_user: STRING; a_password: STRING)
			-- Add a new `a_user' with `a_password'.
			-- Users also get a nonce if we only do basic authentication.
		require
			not exists_user (a_user)
		do
			new_password (a_user, a_password)
		ensure
			exists_user (a_user)
		end


	new_nonce: STRING
			-- Creates a fresh nonce and stores it into `nonce_count', with a nonce-count value of 1.
			-- Returns the nonce.
			-- NOTE: We don't associate the nonce with a user.
		local
			l_nonce: STRING
		do
			l_nonce := new_nonce_value;

			nonce_count.force (0, l_nonce)

			Result := l_nonce
		ensure
			-- TODO
		end

	new_password(a_user: STRING; a_password: STRING)
			-- Associates fresh `a_password' with `a_user'.
		do
			password.force (a_password, a_user)
		ensure
			password.has (a_user)
		end

	increment_nc(user: STRING)
			-- Increment nonce-count associated with `user'.
		require
			exists_user (user)
		local
			l_nc: INTEGER
		do
			l_nc := nonce_count.item (user)
			l_nc := l_nc + 1

			nonce_count.force (l_nc, user)
		ensure
			-- TODO Incremented.
			-- Can we use OLD here?
		end

feature -- status report

	exists_user(a_user: STRING): BOOLEAN
			-- Returns true, if there is a password associated with `a_user'.
		do
			Result := password.has_key (a_user)

--			debug("user-manager")
--				io.putstring ("Knows user " + a_user + ": " + Result.out + "%N")
--				across password.current_keys as cur_key loop io.putstring ("Key: " + cur_key.item + "%N") end
--			end
		end

	exists_nonce(a_nonce: STRING): BOOLEAN
			-- Returns true, if we know `a_nonce'.
		do
			Result := nonce_count.has (a_nonce)
		ensure
			Result implies nonce_count.has (a_nonce)
		end

	is_nonce_stale(a_nonce: STRING): BOOLEAN
			-- Returns true, if nonce has expired, i.e., is too old.
		require
			exists_nonce (a_nonce)
		local
			l_http_date: HTTP_DATE
			l_duration: DATE_TIME_DURATION
			age_in_seconds: INTEGER_64
		do
			l_http_date := get_time_from_nonce (a_nonce)

			l_duration := (create {DATE_TIME}.make_now_utc).relative_duration(l_http_date.date_time)

			age_in_seconds := l_duration.seconds_count

			Result := age_in_seconds > time_to_live

			debug ("user-manager")
				io.putstring ("Age of nonce in seconds: " + age_in_seconds.out + "%N")
				io.putstring ("Nonce stale: " + Result.out + "%N")
			end
		end

feature -- access

	get_password(a_user: STRING): STRING
			-- Get password associated with `a_user'.
		require
			exists_user (a_user)
		do
			if attached password.item (a_user) as l_pw then
				Result := l_pw
			else
					-- This cannot happen.
				Result := ""
				check False end
			end
		end

	get_nc(a_nonce: STRING): INTEGER
			-- Get nonce-count associated with `a_nonce'.
		require
			exists_nonce (a_nonce)
		do
			Result := nonce_count.item (a_nonce)
		end

	get_time_from_nonce(a_nonce: STRING): HTTP_DATE
			-- Get time encoded in nonce associated with `a_user'.
		require
			exists_nonce(a_nonce)
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
				l_decoded_nonce.starts_with (l_time_string)
				l_time_string.same_string (Result.debug_output)
			end

			debug("user-manager")
				io.putstring ("Decoded nonce: " + l_decoded_nonce + "%N")
				io.putstring ("Time in nonce: " + l_time_string + "%N")
				io.putstring ("Result: " + Result.debug_output + "%N")
			end
		end


feature -- private key

	private_key: INTEGER_32
			-- Get the private key of the server
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
	-- All lists have same keys

end
