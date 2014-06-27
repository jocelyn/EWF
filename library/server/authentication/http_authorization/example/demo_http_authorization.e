note
	description : "[
			Simple application root class. 
			Server which supports both basic and digest authentication,
			and can handle multiple users at the same time.
		]"
	date        : "$Date$"
	revision    : "$Revision$"

class
	DEMO_HTTP_AUTHORIZATION

inherit
	WSF_DEFAULT_SERVICE
		redefine
			initialize
		end

	SHARED_HTML_ENCODER

create
	my_make

feature {NONE} -- Initialization

	my_make
		do
			create user_manager.make
			create nonce_manager.make (10)

				-- Insert demo credentials.
			user_manager.put_credentials ("eiffel", "world")
			user_manager.put_credentials ("foo", "bar")
			user_manager.put_credentials ("password", "user")
			user_manager.put_credentials ("Circle Of Life", "Mufasa")

				-- Set parameters.
			server_qop := "auth"
			server_opaque := "5ccc069c403ebaf9f0171e9517f40e41"
			server_algorithm := "MD5"
			server_realm := "Enter password for DEMO"

			make_and_launch
		end

	initialize
			-- Initialize current service.
		do
			set_service_option ("port", 9090)
			set_service_option ("verbose", True)
		end

feature -- Credentials

	is_valid_authentication (a_auth: HTTP_AUTHORIZATION; req: WSF_REQUEST): BOOLEAN
			-- Is `a_auth' authorized basic or digest authentication?
		do
			if a_auth.is_basic then
				Result := a_auth.is_authorized_basic (user_manager)
			else
				check type: a_auth.is_digest end
				Result := a_auth.is_authorized_digest (nonce_manager, user_manager, server_realm, req.request_method, req.request_uri, server_algorithm, server_qop)
			end
		end

feature -- Basic operations

	execute (req: WSF_REQUEST; res: WSF_RESPONSE)
			-- <Precursor>
		local
			l_authenticated_username: like auth_username
		do
				-- Get authentication information, if any.
				-- NOTE: To access result, one could use `auth_username (req)'
			process_authentication (req)

			l_authenticated_username := auth_username (req)

				-- Decide whether authorization is needed.
			if req.path_info.starts_with_general ("/login") then
				if l_authenticated_username /= Void then
					handle_login_authenticated (l_authenticated_username, req, res)
				else
						-- TODO Maybe the first part of the condition could be improved.
					if (not (req.request_uri.has_substring ("auth=basic") or attached req.http_referer as l_ref and then l_ref.has_substring ("auth=basic"))) and (not attached req.http_authorization or (attached {STRING} req.execution_variable (auth_type_variable_name) as s_type and then s_type.is_case_insensitive_equal ("Digest"))) then
						handle_unauthorized ("Please provide credential ...", "Digest", req, res)
					else
						handle_unauthorized ("Please provide credential ...", "Basic", req, res)
					end
				end
			elseif req.path_info.starts_with_general ("/protected/") then
				if l_authenticated_username /= Void then
					handle_restricted_authenticated (l_authenticated_username, req, res)
				else
						-- TODO Maybe the first part of the condition could be improved.
					if (not (req.request_uri.has_substring ("auth=basic") or attached req.http_referer as l_ref and then l_ref.has_substring ("auth=basic"))) and (not attached req.http_authorization or (attached {STRING} req.execution_variable (auth_type_variable_name) as s_type and then s_type.is_case_insensitive_equal ("Digest"))) then
						handle_unauthorized ("This page is restricted to authenticated user!", "Digest", req, res)
					else
						handle_unauthorized ("This page is restricted to authenticated user!", "Basic", req, res)
					end
				end
			else
					-- These areas can be accessed without authentication.

					-- NOTE: The client could have sent an Authorization header for these areas,
					-- even if this is not necessary.
					-- Therefore, we may miss some nonce-counts.
				handle_other (req, res)
			end
		end

	handle_login_authenticated (a_username: READABLE_STRING_8; req: WSF_REQUEST; res: WSF_RESPONSE)
			-- Authentication `a_auth' for login page verified, execute request `req' with response `res'.
		require
			a_username: a_username /= Void
			known_username: user_manager.user_exists (a_username)
		local
			s: STRING
			page: WSF_HTML_PAGE_RESPONSE
		do
			debug("demo_server")
				io.put_string ("Handle login authenticated...%N")
			end

			create s.make_empty

			append_html_header (a_username, req, s)

			s.append ("<p>")
			s.append ("The authenticated user is <strong>")
			s.append (html_encoder.general_encoded_string (a_username))
			s.append ("</strong> ...")
			s.append ("</p>")

			append_html_menu (a_username, req, s)
			append_html_logout (a_username, req, s)
			append_html_footer (req, s)

			create page.make

			if attached auth_digest_authentication_info (req) as l_info then
				page.header.put_header_key_value ({HTTP_HEADER_NAMES}.header_authentication_info, l_info)
			else
				check is_basic: attached auth_type (req) as l_type and then l_type.is_case_insensitive_equal ("Basic") end
			end

			page.set_body (s)
			res.send (page)
		end

	handle_restricted_authenticated (a_authenticated_username: READABLE_STRING_8; req: WSF_REQUEST; res: WSF_RESPONSE)
			-- Authentication `a_auth' for restricted page verified, execute request `req' with response `res'.
		local
			s: STRING
			page: WSF_HTML_PAGE_RESPONSE
		do
			create page.make

			debug("demo_server")
				io.put_string ("Handle restricted authenticated...%N")
			end

			create s.make_empty
			append_html_header (a_authenticated_username, req, s)

			s.append ("<p>")
			s.append ("User <strong>")
			s.append (html_encoder.encoded_string (a_authenticated_username))
			s.append ("</strong>")
			s.append (" has access to this restricted page.")
			s.append ("</p>")

			append_html_menu (a_authenticated_username, req, s)
			append_html_footer (req, s)

			if attached auth_digest_authentication_info (req) as l_info then
				page.header.put_header_key_value ({HTTP_HEADER_NAMES}.header_authentication_info, l_info)
			else
				check no_auth_info: False end
			end

			page.set_body (s)
			res.send (page)
		end

	handle_other (req: WSF_REQUEST; res: WSF_RESPONSE)
			-- No user is authenticated and no authentication needed, execute request `req' with response `res'.
		local
			s: STRING
			page: WSF_HTML_PAGE_RESPONSE
			u: like auth_username
		do
			io.put_string ("DEMO_HTTP_AUTHORIZATION.handle_other")
			io.put_new_line

			u := auth_username (req)

			create s.make_empty
			append_html_header (u, req, s)
			append_html_menu (u, req, s)
			append_html_footer (req, s)

			create page.make
			if attached auth_digest_authentication_info (req) as l_info then
					-- Should we send this if no user is authenticated?
					-- TODO No.
				page.header.put_header_key_value ({HTTP_HEADER_NAMES}.header_authentication_info, l_info)
			end
			page.set_body (s)
			res.send (page)
		end

	handle_unauthorized (a_description: STRING; a_auth_type: READABLE_STRING_8; req: WSF_REQUEST; res: WSF_RESPONSE)
			-- Restricted page or login page, authenticated user is required.
			-- Send `a_description' as part of the response.
		local
			s: STRING
			page: WSF_HTML_PAGE_RESPONSE
			values: LINKED_LIST[STRING]
			new_nonce: STRING
		do

			debug("demo_server")
				io.put_string ("Handle unauthorized...%N")
			end

			create s.make_empty
			append_html_header (Void, req, s)

			s.append ("<p>" + a_description + "</p>")

			append_html_menu (Void, req, s)
			append_html_footer (req, s)

			create page.make
			page.set_status_code ({HTTP_STATUS_CODE}.unauthorized)
			create values.make
			if a_auth_type.is_case_insensitive_equal_general ("digest") then
					-- Digest

					-- Create fresh nonce with nonce-count of zero.
					-- We send this nonce to the user, but we don't know his name yet.
					-- Later, he will send us back the nonce.
				new_nonce := nonce_manager.new_nonce

					-- Create response.
				values.force ("Digest realm=%"" + server_realm +"%"")
				values.force ("qop=%"" + server_qop + "%"")
				values.force ("nonce=%"" + new_nonce + "%"")
				values.force ("opaque=%"" + server_opaque + "%"")
				values.force ("algorithm=" + server_algorithm)

					-- Stale
					-- The stale flag indicates that the previous request from the client was rejected because the nonce value was stale.
					-- If stale is set to true, the client may wish to simply retry the request with a new encrypted response, without
					-- reprompting the user for new credentials.
				if auth_digest_is_stale (req) then
					debug("demo_server")
						io.put_string ("Nonce was stale.%N")
					end

					values.force ("stale=true")
				end

					-- Domains
					-- A list of URIs that define the protection space.
					-- The client can use this list to determine the set of URIs for which the same authentication information may be sent:
					-- any URI that has an URI in this list as a prefix may be assumed to be in the same protection space.
					-- If this directive is omitted or its value is empty, the client should assume that the protection space consist
					-- of all URIs on the responding server.
					--
					-- NOTE: Unfortunately, most major user agents ingore this directive.
	--				-- TODO Test with cURL. Firefox and Chrom just ignore this.
	--			values.force ("domain=%"/login /protected%"")

					-- Create header.
					-- TODO Line continuation for better readability.
				page.header.put_header_key_values ({HTTP_HEADER_NAMES}.header_www_authenticate, values, ", ")
			else
					-- Basic
				values.force ("Basic realm=%"" + server_realm +"%"")
				page.header.put_header_key_values ({HTTP_HEADER_NAMES}.header_www_authenticate, values, ", ")
			end

			page.set_body (s)
			res.send (page)
		end

feature -- Internal: Authentication

	auth_type_variable_name: STRING = "_auth.type"
	auth_username_variable_name: STRING = "_auth.username"
	auth_error_message_variable_name: STRING = "_auth.error_message"
	auth_digest_authentication_info_variable_name: STRING = "_auth.digest.authentication_info"
	auth_digest_stale_variable_name: STRING = "_auth.digest.stale"

	is_authentication_checked (req: WSF_REQUEST): BOOLEAN
			-- Is the request's authorization checked?
		do
			Result := req.http_authorization = Void or else (auth_username (req) /= Void or auth_error_message (req) /= Void)
		end

	is_authenticated (req: WSF_REQUEST): BOOLEAN
			-- Is credentials from request `req' associated with authenticated user?
		require
			is_authentication_checked (req)
		do
			Result := auth_username (req) /= Void
		ensure
			result_correct: Result = (auth_username (req) /= Void)
		end

	process_authentication (req: WSF_REQUEST)
			-- Get authentication information from the request `req'.
			-- NOTE: access information using `auth_* (req: WSF_REQUEST)' function.
		local
			auth: HTTP_AUTHORIZATION
			l_authentication_info: STRING
		do
				-- Reset user data.
			req.unset_execution_variable (auth_username_variable_name)
			req.unset_execution_variable (auth_error_message_variable_name)
			req.unset_execution_variable (auth_digest_authentication_info_variable_name)
			req.unset_execution_variable (auth_digest_stale_variable_name)
			req.unset_execution_variable (auth_type_variable_name)

				-- Get new data, if any.
			if attached req.http_authorization as l_http_authorization then
					-- Try to parse the request.
				create auth.make (l_http_authorization)
				if auth.is_bad_request then
					debug("demo_server")
						io.put_string ("Error while creation of http_auth. Invalid request!")
					end
					req.set_execution_variable (auth_error_message_variable_name, "Invalid request!")
				elseif attached auth.login as l_login then
						-- Check authentication.
					if auth.is_basic then
							-- Basic authentication.
						req.set_execution_variable (auth_type_variable_name, "Basic")
						if is_valid_authentication (auth, req) then
							req.set_execution_variable (auth_username_variable_name, create {IMMUTABLE_STRING_8}.make_from_string (l_login))
						else
							req.set_execution_variable (auth_error_message_variable_name, "Invalid basic credentials for user %"" + l_login + "%"!")
						end
					elseif auth.is_digest then
							-- Digest authentication.
						req.set_execution_variable (auth_type_variable_name, "Digest")
						if is_valid_authentication (auth, req) then
							req.set_execution_variable (auth_username_variable_name, create {IMMUTABLE_STRING_8}.make_from_string (l_login))

							if
								attached user_manager.password (l_login) as l_pwd and then
								attached auth.digest_data as l_digest_data and then
								attached l_digest_data.nonce as l_nonce and then
								nonce_manager.nonce_exists (l_nonce)
							then
									-- Set Authentication-Info.
								l_authentication_info :=  auth.digest_authentication_info (user_manager, req.request_method)
								req.set_execution_variable (auth_digest_authentication_info_variable_name, l_authentication_info)
							else
								check not_allowed: False end
							end

							debug("demo_server")
								io.put_string ("Authorized: True.%N")
								io.put_string ("Computed Authentication-Info%N")
							end
						else
							req.set_execution_variable (auth_error_message_variable_name, "Invalid digest authentication for user %"" + l_login + "%"!")

							debug("demo_server")
								io.put_string ("Authorized: False.%N")
								io.put_string ("Stale: " + auth.stale.out + "%N")
							end

							if auth.stale then
								req.set_execution_variable (auth_digest_stale_variable_name, True)
							end
						end
					else
							--HTTP_AUTHORIZATION requires that this is a bed request.
						check bad_request: auth.is_bad_request end
						req.set_execution_variable (auth_error_message_variable_name, "Unsupported HTTP Authorization for user %"" + l_login + "%"!")
					end
				else
						-- HTTP_AUTHORIZATION invariant prohibits this.
					check login_attached: False end
					req.set_execution_variable (auth_error_message_variable_name, "Missing username value!")
				end
			else
				req.set_execution_variable (auth_error_message_variable_name, "No authentication.")
			end
		ensure
			req.http_authorization /= Void implies auth_username (req) /= Void xor auth_error_message (req) /= Void
		end

	auth_error_message (req: WSF_REQUEST): detachable READABLE_STRING_8
			-- Error message related to authentication attempt.
		do
			if attached {READABLE_STRING_8} req.execution_variable (auth_error_message_variable_name) as m then
				Result := m
			end
		end

	auth_type (req: WSF_REQUEST): detachable READABLE_STRING_8
			-- Authentication type for request `req'.
		do
			if attached {READABLE_STRING_8} req.execution_variable (auth_type_variable_name) as t then
				Result := t
			end
		end

	auth_username (req: WSF_REQUEST): detachable READABLE_STRING_8
			-- Authenticated user name for request `req'.
		do
			if attached {READABLE_STRING_8} req.execution_variable (auth_username_variable_name) as u then
				Result := u
			end
		end

	auth_digest_is_stale (req: WSF_REQUEST): BOOLEAN
			-- Is authentication stale for request `req'.
		do
			Result := req.execution_variable (auth_digest_stale_variable_name) = True
		end

	auth_digest_authentication_info (req: WSF_REQUEST): detachable READABLE_STRING_8
			-- Authentication Info for request `req'.
		do
			if attached {READABLE_STRING_8} req.execution_variable (auth_digest_authentication_info_variable_name) as s then
				Result := s
			end
		end

feature -- Server parameters

	server_qop: STRING
		-- Optional digest directive, but made so only for backward compatibility with RFC 2069.
		-- If present, it describes the quality of protection values supported by the server.

	server_opaque: STRING
		-- String of data, which should be returned by the client unchanged in the Authoriziation header
		-- of subsequent requests with URIs in the same protection space.

	server_algorithm: STRING
		-- String indicating algorithms used to produce the digest and a checksum.

	server_realm: STRING
		-- String to be displayed to users so they know which username and password to use.

feature -- Users

	nonce_manager: MEMORY_NONCE_MANAGER

	user_manager: MEMORY_USER_MANAGER

feature -- Helper

	append_html_header (a_username: detachable READABLE_STRING_8; req: WSF_REQUEST; s: STRING)
			-- Append header paragraph to `s'.
		do
			s.append ("<p>The current page is " + html_encoder.encoded_string (req.path_info) + "</p>")
			s.append ("<p>")
			if a_username /= Void then
				s.append ("User <strong>")
				s.append (html_encoder.encoded_string (a_username))
				s.append ("</strong>")
				append_html_logout (a_username, req, s)
			else
				s.append ("Anonymous visitor")
				append_html_login (req, s)
			end
			s.append ("</p>")
		end

	append_html_menu (a_username: detachable READABLE_STRING_8; req: WSF_REQUEST; s: STRING)
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
			s.append ("<li><a href=%""+ req.script_url ("/login") +"?auth=basic%">sign in (with Basic auth)</a></li>")
			s.append ("<li><a href=%""+ req.script_url ("/login") +"?auth=digest%">sign in (with Digest auth)</a></li>")
		end

	append_html_logout (a_username: detachable READABLE_STRING_8; req: WSF_REQUEST; s: STRING)
			-- Append logout link to `s'.
		local
			l_logout_url: STRING
		do
			l_logout_url := req.absolute_script_url ("/login")

			 	-- Hack to clear http authorization, i.e connect with bad username "_".
			 	-- TODO Maybe there is a cleaner solution than this.
			l_logout_url.replace_substring_all ("://", "://_@")
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

				create hauth.make (l_http_authorization)
				if attached hauth.login as l_login then
					s.append (" login=<strong>" + html_encoder.encoded_string (l_login)+ "</strong>")
				end
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
