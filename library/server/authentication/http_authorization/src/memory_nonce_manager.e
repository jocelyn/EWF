note
	description: "Handles nonce, for digest and basic authentication"

class
	MEMORY_NONCE_MANAGER

inherit
	NONCE_MANAGER

create
	make

feature {NONE} -- initialization

	make (a_ttl: INTEGER)
			-- Set `time_to_live' for nonces to `a_ttl'.
		require
			is_non_negative: a_ttl >= 0
		do
			time_to_live := a_ttl
			create nonce_count_table.make (0)
		ensure
			ttl_set: time_to_live = a_ttl
		end

feature {NONE} -- data

	time_to_live: INTEGER
			-- Time to live for a nonce, in seconds.

feature {NONE} -- data

	nonce_count_table: STRING_TABLE [INTEGER]
			-- For nonce (key), stores current, last seen nonce-count (value).
			-- A nonce is a server-specified data string which should be uniquely generated each time a 401 response is made.
			-- The nonce-count is the hexadecimal count of the number of requests (including the current one) that the client
			-- has sent with the nonce value in this request.
			-- It allows the server to detect request replays.

feature {NONE} -- nonce creation

	new_nonce_value: STRING_8
			-- Create a fresh nonce in the following format:
			--		Base64(timeStamp : MD5(timeStamp : privateKey))
			-- This format allows the server to reject a request if the time-stamp value is not recent enough, i.e.,
			-- the server can limit the time of the nonce's validity.
			-- TODO Create nonce according to suggestion in RFC 2617
			-- This would allow the server to prevent a replay request for an updated version of the resource.
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

			debug("memory_nonce_manager")
				io.put_string ("Nonce before encoding: " + Result + "%N")
			end
		end

feature -- element change

	new_nonce: STRING
			-- Creates a fresh nonce and stores it into `nonce_count_table', with a nonce-count value of 0.
			-- Returns the nonce.
		local
			l_nonce: STRING
		do
			l_nonce := new_nonce_value;

			nonce_count_table.force (0, l_nonce)

			Result := l_nonce
		ensure
			not_empty: not Result.is_empty
			added: (old nonce_count_table.count) + 1 = nonce_count_table.count
		end

	add_nonce (a_nonce: READABLE_STRING_8)
			-- Creates new nonce `a_nonce' and stores it into `nonce_count_table', with a nonce-count value of 0.
		require
			unknown_nonce: not nonce_exists(a_nonce)
		do

			nonce_count_table.force (0, a_nonce)
		ensure
			added: nonce_exists (a_nonce)
			nc_zero: nonce_count (a_nonce) = 0
		end

--	increment_nonce_count (a_nonce: STRING)
--			-- Increment nonce-count associated with `user'.
--		require
--			nonce_known: nonce_exists (a_nonce)
--		local
--			l_nc: INTEGER
--		do
--			l_nc := nonce_count_table.item (a_nonce)


--			debug ("user-manager")
--				io.putstring ("Old nonce-count: " + l_nc.out + "%N")
--			end


--			l_nc := l_nc + 1


--			debug ("user-manager")
--				io.putstring ("New nonce-count: " + l_nc.out + "%N")
--			end

--			nonce_count_table.force (l_nc, a_nonce)
--		ensure
--				-- FIXME
--			incremented: (old nonce_count_table).item (a_nonce) = nonce_count_table.item (a_nonce) + 1
--		end

feature -- status report

	nonce_exists (a_nonce: READABLE_STRING_8): BOOLEAN
			-- Is nonce `a_nonce' known?
		do
			Result := nonce_count_table.has (a_nonce)
		ensure then
			result_correct: (Result implies nonce_count_table.has (a_nonce)) and (not Result implies not nonce_count_table.has (a_nonce))
		end

	is_nonce_stale (a_nonce: READABLE_STRING_8): BOOLEAN
			-- True, if nonce exists and has expired, i.e., is older than `time_to_live'.
		local
			dt: DATE_TIME
			l_duration: DATE_TIME_DURATION
			age_in_seconds: INTEGER_64
		do
			dt := time_from_nonce (a_nonce)

			l_duration := (create {DATE_TIME}.make_now_utc).relative_duration (dt)

			age_in_seconds := l_duration.seconds_count

			Result := age_in_seconds > time_to_live

			debug ("memory_nonce_manager")
				io.putstring ("Age of nonce in seconds: " + age_in_seconds.out + "%N")
				io.putstring ("Nonce stale: " + Result.out + "%N")
			end
		end

feature -- access

	nonce_count (a_nonce: READABLE_STRING_8): INTEGER
			-- Nonce-count associated with `a_nonce', or zero, if `a_nonce' is unknown.
		do
			Result := nonce_count_table.item (a_nonce)
		end

	set_nonce_count (a_nonce: READABLE_STRING_8; a_nonce_count: INTEGER)
			-- Set nonce-count associated with `a_nonce' to `a_nonce_count'.
		do
			nonce_count_table.force (a_nonce_count, a_nonce)
		end

	time_from_nonce (a_nonce: READABLE_STRING_8): DATE_TIME
			-- Time encoded in `a_nonce'.
		require
			nonce_known: nonce_exists(a_nonce)
		local
			l_base_decoder: BASE64
			l_decoded_nonce: STRING
			l_time_string: STRING
			l_index: INTEGER
			l_http_date: HTTP_DATE
		do
			create l_base_decoder

				-- Read the time from the nonce.

			l_decoded_nonce := l_base_decoder.decoded_string (a_nonce)

			l_index := l_decoded_nonce.last_index_of (':', l_decoded_nonce.count)

			l_time_string := l_decoded_nonce.substring (1, l_index - 1)

			debug("memory_nonce_manager")
				io.put_string ("Index: " + l_index.out + "%N")
				io.put_string ("Time string: " + l_time_string + "%N")
			end

				-- Create result from this time.

			create l_http_date.make_from_string (l_time_string)
			check
				prefix_correct: l_decoded_nonce.starts_with (l_time_string)
				result_object: l_time_string.same_string (l_http_date.debug_output)
			end

			Result := l_http_date.date_time
		end

feature -- private key

	private_key: INTEGER_32
			-- Get or compute the private key of the server.
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

			debug("memory_nonce_manager")
				io.put_string ("Private key: " + private_key.out + "%N")
			end
		end


invariant
	-- TODO
end
