note
	description : "simple application root class. This demo is for just one client!"
	date        : "$Date$"
	revision    : "$Revision$"

class
	DEMO_BASIC

inherit
	WSF_DEFAULT_SERVICE
		redefine
			initialize
		end

	SHARED_HTML_ENCODER

create
	make_and_launch

feature {NONE} -- Initialization

	initialize
			-- Initialize current service.
		do
			set_service_option ("port", 9090)
			set_service_option ("verbose", True)

			init_private_key

			create server_nonce_list.make (0)
		end

feature -- Credentials

	is_known_login (a_login: READABLE_STRING_GENERAL): BOOLEAN
			-- Is `a_login' a known username?
		do
			Result := valid_credentials.has (a_login)
		end

	is_valid_credential (a_login: READABLE_STRING_GENERAL; a_password: detachable READABLE_STRING_GENERAL): BOOLEAN
			-- Is `a_login:a_password' a valid credential?
		do
			if
				a_password /= Void and
				attached valid_credentials.item (a_login) as l_passwd
			then
				Result := a_password.is_case_insensitive_equal (l_passwd)
			end
		ensure
			Result implies is_known_login (a_login)
		end

--	demo_credential: STRING_32
--			-- First valid known credential display for demo in dialog.
--		do
--			valid_credentials.start
--			create Result.make_from_string_general (valid_credentials.key_for_iteration)
--			Result.append_character (':')
--			Result.append (valid_credentials.item_for_iteration)
--		end

	valid_credentials: STRING_TABLE [READABLE_STRING_32]
			-- Password indexed by login.
		once
			create Result.make_caseless (3)
			Result.force ("world", "eiffel")
			Result.force ("bar", "foo")
			Result.force ("password", "user")
			Result.force ("Circle Of Life", "Mufasa")
		ensure
			not Result.is_empty
		end

feature -- Basic operations

	execute (req: WSF_REQUEST; res: WSF_RESPONSE)
			-- <Precursor>
		local
			l_authenticated_username: detachable READABLE_STRING_32
			l_valid_credential: BOOLEAN
			content_from_input: STRING_8
			header: HTTP_HEADER
			iter: ITERABLE [TUPLE [READABLE_STRING_8, READABLE_STRING_8]]
			auth: HTTP_AUTHORIZATION
			arr: ARRAYED_LIST [TUPLE [READABLE_STRING_8, READABLE_STRING_8]]
			auth_successful: BOOLEAN
			auth_stale: BOOLEAN
		do
			-- Hanle requests which contain Authorization header.
			if attached req.http_authorization as l_http_auth then
--				-- Try to parse the request

				-- Once, add a nonce, s.t. we can test stale
				add_nonce_once

				create auth.make (l_http_auth)

				if auth.error_occurred then
					io.putstring ("Error while creation of http_auth.")
				else
					-- Test whether we know the username.
					if
						attached auth.login as attached_auth_login and then not attached_auth_login.is_empty
					then
						if
							attached valid_credentials.item (attached_auth_login) as attached_auth_password
						then
							-- We have everything we need to verify the received response.

							-- TODO Check that the field "uri" of the authorization-header is ok.
							-- TODO Then use this field in the is_authorized.

							-- TODO Distinguish between basic and digest.
							auth_successful := auth.is_authorized (attached_auth_login, attached_auth_password, server_realm, server_nonce_list, req.request_method, req.request_uri, server_algorithm, void, server_qop)

							auth_stale := auth.stale

							io.putstring ("Stale: " + auth_stale.out + "%N")

							-- TODO Replace this with above
--							auth_successful := auth.is_authorized (attached_auth_login, attached_auth_password, server_realm, server_nonce, req.request_method, "/dir/index.html", server_algorithm, void, server_qop)

							l_authenticated_username := attached_auth_login

							io.putstring ("Is authorized: " + auth_successful.out + "%N")

							-- TODO Replace this.
							-- TODO The problem was that at the other place, it complained that "auth is not properly set..."
							if auth_successful then
								handle_authenticated (auth, req, res)
							end
						else
							io.putstring ("We don't know this login: " + attached_auth_login)
						end
					else
						io.putstring ("HTTP_AUTHORIZATION was not able to parse login successuflly.%N")
					end

				end
			else
--				io.putstring ("DEMO_BASICS.execute: request is not http authorization.")
--				io.put_new_line
			end

			if not auth_successful then
				handle_unauthorized ("ERROR: Invalid credential", req, res, auth_stale)
			else
				if l_authenticated_username /= Void then
					-- TODO We would like to call "handle_authenticated" here.
				elseif req.path_info.same_string_general ("/login") then
					handle_unauthorized ("Please provide credential ...", req, res, auth_stale)
				elseif req.path_info.starts_with_general ("/protected/") then
						-- any "/protected/*" url
					handle_unauthorized ("Protected area, please sign in before", req, res, auth_stale)
				else
					handle_anonymous (req, res)
				end
			end
		end

	handle_authenticated (auth: HTTP_AUTHORIZATION; req: WSF_REQUEST; res: WSF_RESPONSE)
			-- User `a_username' is authenticated, execute request `req' with response `res'.
		require
			valid_username: attached auth.login as attached_login and then not attached_login.is_empty
			known_username: is_known_login (attached_login)
			auth_exists_and_authorized: attached auth and then not auth.is_bad_request
		local
			s: STRING
			page: WSF_HTML_PAGE_RESPONSE
			values: LINKED_LIST[STRING]
			rspauth: STRING_8
			HA1, HA2: STRING_8
		do
			io.putstring ("DEMO_BASIC.handle_authenticated")
			io.put_new_line

			if attached auth as attached_auth and then
				attached attached_auth.login as attached_login
			then
				create s.make_empty

				append_html_header (req, s)

				s.append ("<p>The authenticated user is <strong>")
				s.append (html_encoder.general_encoded_string (attached_login))
				s.append ("</strong> ...</p>")

				append_html_menu (attached_login, req, s)
				append_html_logout (attached_login, req, s)
				append_html_footer (req, s)

				create page.make

				if attached_auth.is_digest then
					-- Add Authentication-Info header
					create values.make

					if attached attached_auth.qop_value as attached_qop and then not attached_qop.is_empty then
						check
							is_auth: attached_qop.is_case_insensitive_equal ("auth")
						end

						values.force ("qop=%"" + attached_qop + "%"")

						check
							is_cnonce_attached: attached attached_auth.cnonce_value as attached_cnonce and then not attached_cnonce.is_empty
							is_nc_attached: attached attached_auth.nc_value as attached_nc and then not attached_nc.is_empty
						end
					end

					if attached attached_auth.cnonce_value as attached_cnonce and then not attached_cnonce.is_empty then
						values.force ("cnonce=%"" + attached_cnonce + "%"")
					end

					if attached attached_auth.nc_value as attached_nc and then not attached_nc.is_empty then
						values.force ("nc=%"" + attached_nc + "%"")
					end

					if
						attached attached_auth.realm_value as attached_realm_value and
						attached valid_credentials.item (attached_login) as attached_server_password and
						attached server_realm as attached_server_realm and
						attached req.request_method as attached_server_method and
						attached req.request_method as attached_server_uri and
						attached server_nonce_list as attached_server_nonce_list
					then
						HA1 := attached_auth.compute_hash_a1 (attached_login, attached_server_realm, attached_server_password, server_algorithm, server_nonce_list.last)

						HA2 := attached_auth.compute_hash_a2 (attached_server_method, attached_server_uri, server_algorithm, void, server_qop, true)

						rspauth := attached_auth.compute_expected_response (HA1, HA2, server_nonce_list.last, server_qop, server_algorithm, attached_auth.nc_value, attached_auth.cnonce_value)

						-- TODO Replace
						-- TODO What happens rspauth is wrong?
--						values.force ("rspauth=%"" + "abcd" + "%"")


						values.force ("rspauth=%"" + rspauth + "%"")
					end

					-- Coma + CRLF + space : ",%/13/%/10/%/13/ "
					page.header.put_header_key_values ({HTTP_HEADER_NAMES}.header_authentication_info, values, ", ")
				end

				page.set_body (s)


				print("page.header.string:%N")
				PRINT(page.header.string)
				io.new_line

				res.send (page)
			else
				-- TODO This cannot happen...
				io.putstring ("ERROR: This should not happen.")
			end
		end

	handle_anonymous (req: WSF_REQUEST; res: WSF_RESPONSE)
			-- No user is authenticated, execute request `req' with response `res'.
		local
			s: STRING
			page: WSF_HTML_PAGE_RESPONSE
		do
			io.putstring ("DEMO_BASIC.handle_anonymous")
			io.put_new_line

			create s.make_empty
			append_html_header (req, s)

			s.append ("Anonymous visitor ...<br/>")

			append_html_login (req, s)
			append_html_menu (Void, req, s)
			append_html_footer (req, s)

			create page.make
			page.set_body (s)
			res.send (page)
		end

	handle_unauthorized (a_description: STRING; req: WSF_REQUEST; res: WSF_RESPONSE; stale: BOOLEAN)
			-- Restricted page, authenticated user is required.
			-- Send `a_description' as part of the response.
			-- TODO Result could be stale.
		local
			h: HTTP_HEADER
			s: STRING
			page: WSF_HTML_PAGE_RESPONSE
			values: LINKED_LIST[STRING]
			new_nonce: STRING
		do
			io.putstring ("HANDLE_UNAUTHORIZED%N")

			create s.make_from_string (a_description)

			append_html_login (req, s)
			append_html_menu (Void, req, s)
			append_html_footer (req, s)

			create page.make
			page.set_status_code ({HTTP_STATUS_CODE}.unauthorized)
--			page.header.put_header_key_value ({HTTP_HEADER_NAMES}.header_www_authenticate,
--					"Basic realm=%"Please enter a valid username and password (demo [" + html_encoder.encoded_string (demo_credential) + "])%""
--					--| warning: for this example: a valid credential is provided in the message, of course that for real application.
--				)

			create values.make

			values.force ("Digest realm=%"" + server_realm +"%"")
			values.force ("qop=%"" + server_qop + "%"")

			-- Get a fresh nonce.
			new_nonce := getfreshnonce

			server_nonce_list.force (new_nonce)

			values.force ("nonce=%"" + new_nonce + "%"")
			values.force ("opaque=%"" + server_opaque + "%"")
			values.force ("algorithm=" + server_algorithm + "")

			-- TODO Remove this
--			values.force ("domain%"" + "/login" + "%"")

			-- Stale
			if stale then
				io.putstring ("Nonce was stale.%N")

				values.force ("stale=true")
			end
			-- Coma + CRLF + space : ",%/13/%/10/%/13/ "
			page.header.put_header_key_values ({HTTP_HEADER_NAMES}.header_www_authenticate, values, ", ")

--			-- ETag
--			page.header.put_header_key_value ({HTTP_HEADER_NAMES}.header_etag, "%"686897696a7c876b7e%"")

			page.set_body (s)

--			print("page.header.string:%N")
			PRINT(page.header.string)
			io.new_line

--			print("page.body:%N")
--			print(page.body)
--			io.new_line

			res.send (page)
		end

feature -- Parameters

	-- TODO Also support auth-int.	
	-- TODO If we suggest multiple alternatives, use an arrayed_list istead.
	server_qop: STRING = "auth"
--	server_nonce: STRING
	server_opaque: STRING = "5ccc069c403ebaf9f0171e9517f40e41"
	server_algorithm: STRING = "MD5"
	server_realm: STRING = "testrealm@host.com"

	-- TODO This could be a list of Tuples, s.t. each nonce is assigned the latest nc from the client.
	server_nonce_list: ARRAYED_LIST[STRING]

	private_key: INTEGER_32


feature -- Nonce

	getFreshNonce: STRING_8
			-- Create a fresh nonce in the following format:
			--		Base64(timeStamp : MD5(timeStamp : privateKey))
			-- TODO Create nonce according to suggestion in RFC 2617
		require
			private_key_exists: attached private_key
		local
			nonce_string: STRING_8
			date_time: DATE_TIME
			http_time: HTTP_DATE
			base64_encoder: BASE64
			hash: MD5
			time_string: STRING_8
		do
			create base64_encoder

			create hash.make

			create date_time.make_now_utc

			create http_time.make_from_date_time (date_time)

			time_string := http_time.string

--			io.putstring ("Time: " + time_string + "%N")

			hash.update_from_string (time_string + ":" + private_key.out)

			Result := hash.digest_as_string
			Result.to_lower
			Result.prepend (time_string + ":")

--			io.putstring ("Nonce before encoding: " + Result + "%N")

			Result := base64_encoder.encoded_string (Result)

--			io.putstring ("Nonce: " + Result + "%N")
		end


	init_private_key
			-- Initialize the private key.
			-- FIXME We always want a new private key...
			-- TODO Call this at proper place.
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

			private_key := random_int.item

			io.putstring ("Private key: " + private_key.out + "%N")
		end



		-- TODO Test by simply adding a nonce to the server list.
		-- Make method ONCE ADD NONCE.
		add_nonce_once
			once
				io.putstring ("Called add_nonce_once%N")
				server_nonce_list.force (getfreshnonce)
			end


feature -- Helper

	append_html_header (req: WSF_REQUEST; s: STRING)
			-- Append header paragraph to `s'.
		do
			s.append ("<p>The current page is " + html_encoder.encoded_string (req.path_info) + "</p>")
		end

	append_html_menu (a_username: detachable READABLE_STRING_32; req: WSF_REQUEST; s: STRING)
			-- Append menu to `s'.
			-- when an user is authenticated, `a_username' is attached.
		do
			if a_username /= Void then
				s.append ("<li><a href=%""+ req.absolute_script_url ("") +"%">Your account</a> (displayed only is user is authenticated!)</li>")
			end
			s.append ("<li><a href=%""+ req.absolute_script_url ("") +"%">home</a></li>")
			s.append ("<li><a href=%""+ req.script_url ("/public/area") +"%">public area</a></li>")
			s.append ("<li><a href=%""+ req.script_url ("/protected/area") +"%">protected area</a></li>")
		end

	append_html_login (req: WSF_REQUEST; s: STRING)
			-- Append login link to `s'.
		do
			s.append ("<li><a href=%""+ req.script_url ("/login") +"%">sign in</a></li>")
		end

	append_html_logout (a_username: detachable READABLE_STRING_32; req: WSF_REQUEST; s: STRING)
			-- Append logout link to `s'.
		local
			l_logout_url: STRING
		do
			l_logout_url := req.absolute_script_url ("/login")
			l_logout_url.replace_substring_all ("://", "://_@") -- Hack to clear http authorization, i.e connect with bad username "_".
			s.append ("<li><a href=%""+ l_logout_url +"%">logout</a></li>")
		end

	append_html_footer (req: WSF_REQUEST; s: STRING)
			-- Append html footer to `s'.
		local
			hauth: HTTP_AUTHORIZATION
		do
			s.append ("<hr/>")
			if attached req.http_authorization as l_http_authorization then
				s.append ("Has <em>Authorization:</em> header: ")

				io.putstring ("DEMO_BASIC.append_html_footer()%N")

--				create hauth.make (req.http_authorization)
--				if attached hauth.login as l_login then
--					s.append (" login=<strong>" + html_encoder.encoded_string (l_login)+ "</strong>")
--				end
--				if attached hauth.password as l_password then
--					s.append (" password=<strong>" + html_encoder.encoded_string (l_password)+ "</strong>")
--				end
				s.append ("<br/>")
			end
			if attached req.raw_header_data as l_header then
					-- Append the raw header data for information
				s.append ("Raw header data:")
				s.append ("<pre>")
				s.append (l_header)
				s.append ("</pre>")
			end
		end
end
