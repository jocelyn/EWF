note
	description: "Summary description for {REQUEST_HANDLER}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

deferred class
	REQUEST_HANDLER

feature {NONE} -- Initialization

	initialize
			-- Initialize various attributes
		do
			create {LINKED_LIST [like parameters.item]} parameters.make
			create {LINKED_LIST [like uri_parameters.item]} uri_parameters.make
			set_format_located_before_parameters
		end

feature -- Access

	description: detachable STRING
			-- Optional description

	parameters: LIST [REQUEST_HANDLER_PARAMETER]
			-- Parameters information

	uri_parameters: LIST [REQUEST_HANDLER_URI_PARAMETER]
			-- URI Parameters information			

feature -- Access: Format

	supported_request_method_names: LIST [STRING]
			-- Support request method such as GET, POST, ...
		do
			create {LINKED_LIST [STRING]} Result.make
			if method_get_supported then
				Result.extend (request_method_constants.method_get_name)
			end
			if method_post_supported then
				Result.extend (request_method_constants.method_post_name)
			end
			if method_put_supported then
				Result.extend (request_method_constants.method_put_name)
			end
			if method_delete_supported then
				Result.extend (request_method_constants.method_delete_name)
			end
			if method_head_supported then
				Result.extend (request_method_constants.method_head_name)
			end
		end

	supported_format_names: LIST [STRING]
			-- Support request format result such as json, xml, ...
		do
			create {LINKED_LIST [STRING]} Result.make
			Result.compare_objects
			if format_json_supported then
				Result.extend (format_constants.json_name)
			end
			if format_xml_supported then
				Result.extend (format_constants.xml_name)
			end
			if format_text_supported then
				Result.extend (format_constants.text_name)
			end
			if format_html_supported then
				Result.extend (format_constants.html_name)
			end
			if format_rss_supported then
				Result.extend (format_constants.rss_name)
			end
			if format_atom_supported then
				Result.extend (format_constants.atom_name)
			end
		end

	default_format_name: detachable STRING
		do
			if attached supported_format_names as lst and then not lst.is_empty then
				Result := lst.first
			end
		end

	format_located_after_parameters: BOOLEAN
			--| path = app-path/parameters{.format}	
		do
			Result := format_path_location = opt_format_located_after_parameters
		end

	format_located_before_parameters: BOOLEAN
			--| path = app-path{.format}/parameters
		do
			Result := format_path_location = opt_format_located_before_parameters
		end

	set_format_located_after_parameters
		do
			format_path_location := opt_format_located_after_parameters
		end

	set_format_located_before_parameters
		do
			format_path_location := opt_format_located_before_parameters
		end

feature {NONE} -- Format path location

	format_path_location: INTEGER

	opt_format_located_before_parameters: INTEGER = 1

	opt_format_located_after_parameters: INTEGER = 2

feature -- Status report

	is_valid_context (req: GW_REQUEST): BOOLEAN
			-- Is `req' valid context for current handler?
		do
			Result := request_method_name_supported (req.environment.request_method)
		end

feature -- Execution

	execute (a_path: STRING; req: GW_REQUEST; res: GW_RESPONSE)
			-- Execute request handler	
		require
			is_valid_context: is_valid_context (req)
		local
			l_format, l_args: detachable STRING
			rescued: BOOLEAN
		do
			if not rescued then
				if attached execution_information (req) as l_info then
					l_format := l_info.format
					l_args := l_info.arguments
				end
				if request_method_name_supported (req.environment.request_method) then
					pre_execute (req)
					execute_application (a_path, req, res, l_format, l_args)
					post_execute (req, res)
				else
					execute_method_not_allowed (req, res, l_format, l_args)
				end
			else
				rescue_execute (req, res)
			end
		rescue
			rescued := True
			retry
		end

--	execute_unauthorized (req: GW_REQUEST; res: GW_RESPONSE; a_format: detachable STRING; a_args: detachable STRING)
--		local
--			h: GW_HEADER
--		do
--			create h.make
--			h.put_status ({HTTP_STATUS_CODE}.unauthorized)
--			h.put_header ("WWW-Authenticate: Basic realm=%"Eiffel auth%"")
--			res.write_string (h.string)
--			h.recycle
--		end

	execute_method_not_allowed (req: GW_REQUEST; res: GW_RESPONSE; a_format: detachable STRING; a_args: detachable STRING)
		local
			h: GW_HEADER
			s: STRING
			lst: LIST [STRING]
		do
			create h.make
			h.put_status ({HTTP_STATUS_CODE}.method_not_allowed)
			create s.make_from_string ("Allow: ")
			from
				lst := supported_request_method_names
				lst.start
			until
				lst.after
			loop
				s.append_string (lst.item)
				if not lst.islast then
					s.append_character (',')
					s.append_character (' ')
				end
				lst.forth
			end
			h.put_header (s)
			res.write_string (h.string)
			h.recycle
		end

	execute_application (a_path: STRING; req: GW_REQUEST; res: GW_RESPONSE; a_format: detachable STRING; a_args: detachable STRING)
			-- Execute request handler with `a_format' ad `a_args'
		deferred
		end

	pre_execute (req: GW_REQUEST)
			-- Operation processed before `execute'
		do
			--| To be redefined if needed
		end

	post_execute (req: GW_REQUEST; res: GW_RESPONSE)
			-- Operation processed after `execute'
		do
			--| To be redefined if needed
		end

	rescue_execute (req: GW_REQUEST; res: GW_RESPONSE)
			-- Operation processed after a rescue
		do
			--| To be redefined if needed
			post_execute (req, res)
		end

feature -- Execution: report

	execution_information (req: GW_REQUEST): detachable TUPLE [format: detachable STRING; arguments: detachable STRING]
			-- Execution information related to the request
		do
			Result := path_information (req, req.environment.path_info)
		end

	path_information (req: GW_REQUEST; a_rq_path: STRING): detachable TUPLE [format: detachable STRING; arguments: detachable STRING]
			-- Information related to `a_path'
		local
			l_rq_path: STRING
			i,p,n: INTEGER
			l_format, l_args: detachable STRING
		do
			l_rq_path := a_rq_path
			if l_rq_path.count > 0 and then l_rq_path[1] /= '/' then
				l_rq_path := "/" + l_rq_path
			end
			n := l_rq_path.count
			i := req.environment.path_info.count + 1

			if format_located_before_parameters then
					--| path = app-path{.format}/parameters

				if l_rq_path.valid_index (i) and then l_rq_path[i] = '.' then
					p := l_rq_path.index_of ('/', i + 1)
					if p = 0 then
						p := n + 1
					else
						l_args := l_rq_path.substring (p + 1, n)
					end
					l_format := l_rq_path.substring (i + 1, p - 1)
				elseif n > i then
					check l_rq_path[i] = '/' end
					l_args := l_rq_path.substring (i + 1, n)
				end
			elseif format_located_after_parameters then
					--| path = app-path/parameters{.format}

				p := l_rq_path.last_index_of ('.', n)
				if p > i then
					l_format := l_rq_path.substring (p + 1, n)
					l_args := l_rq_path.substring (i + 1, p - 1)
				elseif n > i then
					check l_rq_path[i] = '/' end
					l_format := Void
					l_args := l_rq_path.substring (i + 1, n)
				end
			end
			if l_format /= Void or l_args /= Void then
				Result := [l_format, l_args]
			end
		end

	url (req: GW_REQUEST; args: detachable STRING; abs: BOOLEAN): STRING
			-- Associated url based on `path' and `args'
			-- if `abs' then return absolute url
		local
			s: detachable STRING
		do
			s := args
			if s /= Void and then s.count > 0 then
				if s[1] /= '/' then
					s := req.environment.request_uri + "/" + s
				else
					s := req.environment.request_uri + s
				end
			else
				s := req.environment.request_uri
			end
			if abs then
				Result := req.script_absolute_url (s)
			else
				Result := req.script_url (s)
			end
		ensure
			result_attached: Result /= Void
		end

	hidden (req: GW_REQUEST): BOOLEAN
			-- Do we hide this application in service publishing
		do
			--| By default: False
		end

feature -- Access: parameters

--	parameter (n: STRING): detachable REQUEST_HANDLER_PARAMETER
--			-- Parameter's object for `n'.	
--		require
--			n_not_empty: n /= Void and then not n.is_empty
--		local
--			params: like parameters
--		do
--			from
--				params := parameters
--				params.start
--			until
--				Result /= Void or params.after
--			loop
--				Result := params.item
--				if not n.same_string (Result.name) then
--					Result := Void
--					params.forth
--				end
--			end
--		ensure
--			result_valid: Result /= Void implies n.same_string (Result.name)
--		end

	parameter_value (p: REQUEST_HANDLER_PARAMETER; req: GW_REQUEST): detachable STRING_32
			-- Parameter's value for `n'.
		do
			if attached {REQUEST_HANDLER_URI_PARAMETER} p as p_uri then
				-- ...
			else
				if method_get_supported then
					Result := req.parameter (p.name)
				end
				if Result = Void and method_post_supported then
					Result := req.form_field (p.name)
				end
			end
		end

--	uri_parameter (n: STRING): detachable REQUEST_HANDLER_URI_PARAMETER
--			-- Parameter's object for `n'.	
--		require
--			n_not_empty: n /= Void and then not n.is_empty
--		local
--			params: like uri_parameters
--		do
--			from
--				params := uri_parameters
--				params.start
--			until
--				Result /= Void or params.after
--			loop
--				Result := params.item
--				if not n.same_string (Result.name) then
--					Result := Void
--					params.forth
--				end
--			end
--		ensure
--			result_valid: Result /= Void implies n.same_string (Result.name)
--		end

feature -- Analyze: parameters

	analyze_parameters (results: HASH_TABLE [STRING_32, STRING]; missings: LIST [STRING]; req: GW_REQUEST)
			-- Analyze parameters from `req', and return in `results' the table of known parameters
			-- return in `missings' the required parameters which are missing if any
		require
			results_attached: results /= Void
			missing_attached: missings /= Void
		local
			params: like parameters
			param: like parameters.item
			n: STRING
		do
				--| GET,POST,.. parameters
			from
				params := parameters
				params.start
			until
				params.after
			loop
				param := params.item
				n := param.name
				if attached parameter_value (param, req) as v then
					results.put (v, n)
				elseif not param.optional then
					missings.force (n)
				end
				params.forth
			end

				--| URI parameters
			from
				params := uri_parameters
				params.start
			until
				params.after
			loop
				param := params.item
				n := param.name
				if attached parameter_value (param, req) as v then
					results.put (v, n)
				elseif not param.optional then
					missings.force (n)
				end
				params.forth
			end
		end

feature -- Element change

--	set_path (a_path: like path)
--		require
--			a_path_valid: a_path.count > 1 and then a_path[1] = '/'
--		do
--			path := a_path.string
--		end

	set_description (s: like description)
			-- Set `description' to `s'
		do
			description := s
		end

feature {NONE} -- Implementation

	supported_request_methods: INTEGER
			-- Support request method such as GET, POST, ...

	supported_formats: INTEGER
			-- Support request format result such as json, xml, ...

feature {NONE} -- Status report

	format_id_supported (a_id: INTEGER): BOOLEAN
		do
			Result := (supported_formats & a_id) = a_id
		end

	format_name_supported (n: STRING): BOOLEAN
			-- Is format `n' supported?
		do
			Result := format_id_supported (format_constants.format_id (n))
		end

	format_constants: HTTP_FORMAT_CONSTANTS
		once
			create Result
		end

feature {NONE} -- Status report

	request_method_id_supported (a_id: INTEGER): BOOLEAN
		do
			Result := (supported_request_methods & a_id) = a_id
		end

	request_method_name_supported (n: STRING): BOOLEAN
			-- Is request method `n' supported?
		do
			Result := request_method_id_supported (request_method_constants.method_id (n))
		end

	request_method_constants: HTTP_REQUEST_METHOD_CONSTANTS
		once
			create Result
		end

feature -- Status report		

	format_json_supported: BOOLEAN
		do
			Result := format_id_supported ({HTTP_FORMAT_CONSTANTS}.json)
		end

	format_xml_supported: BOOLEAN
		do
			Result := format_id_supported ({HTTP_FORMAT_CONSTANTS}.xml)
		end

	format_text_supported: BOOLEAN
		do
			Result := format_id_supported ({HTTP_FORMAT_CONSTANTS}.text)
		end

	format_html_supported: BOOLEAN
		do
			Result := format_id_supported ({HTTP_FORMAT_CONSTANTS}.html)
		end

	format_rss_supported: BOOLEAN
		do
			Result := format_id_supported ({HTTP_FORMAT_CONSTANTS}.rss)
		end

	format_atom_supported: BOOLEAN
		do
			Result := format_id_supported ({HTTP_FORMAT_CONSTANTS}.atom)
		end

	method_get_supported: BOOLEAN
		do
			Result := request_method_id_supported ({HTTP_REQUEST_METHOD_CONSTANTS}.method_get)
		end

	method_post_supported: BOOLEAN
		do
			Result := request_method_id_supported ({HTTP_REQUEST_METHOD_CONSTANTS}.method_post)
		end

	method_put_supported: BOOLEAN
		do
			Result := request_method_id_supported ({HTTP_REQUEST_METHOD_CONSTANTS}.method_put)
		end

	method_delete_supported: BOOLEAN
		do
			Result := request_method_id_supported ({HTTP_REQUEST_METHOD_CONSTANTS}.method_delete)
		end

	method_head_supported: BOOLEAN
		do
			Result := request_method_id_supported ({HTTP_REQUEST_METHOD_CONSTANTS}.method_head)
		end

feature -- Element change: parameters

	add_uri_parameter (n: STRING; d: detachable STRING; opt: BOOLEAN; a_type: detachable STRING)
		local
			p: like uri_parameters.item
		do
			create p.make (n, opt)
			p.description := d
			p.type := a_type
			uri_parameters.extend (p)
		end

	add_boolean_uri_parameter (n: STRING; d: detachable STRING; opt: BOOLEAN)
		do
			add_uri_parameter (n, d, opt, "boolean")
		end

	add_integer_uri_parameter (n: STRING; d: detachable STRING; opt: BOOLEAN)
		do
			add_uri_parameter (n, d, opt, "integer")
		end

	add_string_uri_parameter (n: STRING; d: detachable STRING; opt: BOOLEAN)
		do
			add_uri_parameter (n, d, opt, "string")
		end

	add_parameter (n: STRING; d: detachable STRING; opt: BOOLEAN; a_type: detachable STRING)
		local
			p: like parameters.item
		do
			create p.make (n, opt)
			p.description := d
			p.type := a_type
			parameters.extend (p)
		end

	add_boolean_parameter (n: STRING; d: detachable STRING; opt: BOOLEAN)
		do
			add_parameter (n, d, opt, "boolean")
		end

	add_integer_parameter (n: STRING; d: detachable STRING; opt: BOOLEAN)
		do
			add_parameter (n, d, opt, "integer")
		end

	add_string_parameter (n: STRING; d: detachable STRING; opt: BOOLEAN)
		do
			add_parameter (n, d, opt, "string")
		end

feature -- Element change: request methods		

	reset_supported_request_methods
		do
			supported_request_methods := 0
		end

	enable_request_method_get
		do
			enable_request_method ({HTTP_REQUEST_METHOD_CONSTANTS}.method_get)
		end

	enable_request_method_post
		do
			enable_request_method ({HTTP_REQUEST_METHOD_CONSTANTS}.method_post)
		end

	enable_request_method_put
		do
			enable_request_method ({HTTP_REQUEST_METHOD_CONSTANTS}.method_put)
		end

	enable_request_method_delete
		do
			enable_request_method ({HTTP_REQUEST_METHOD_CONSTANTS}.method_delete)
		end

	enable_request_method_head
		do
			enable_request_method ({HTTP_REQUEST_METHOD_CONSTANTS}.method_head)
		end

	enable_request_method (m: INTEGER)
		do
			supported_request_methods := supported_request_methods | m
		end

feature -- Element change: formats

	reset_supported_formats
		do
			supported_formats := 0
		end

	enable_format_json
		do
			enable_format ({HTTP_FORMAT_CONSTANTS}.json)
		end

	enable_format_xml
		do
			enable_format ({HTTP_FORMAT_CONSTANTS}.xml)
		end

	enable_format_text
		do
			enable_format ({HTTP_FORMAT_CONSTANTS}.text)
		end

	enable_format_html
		do
			enable_format ({HTTP_FORMAT_CONSTANTS}.html)
		end

	enable_format (f: INTEGER)
		do
			supported_formats := supported_formats | f
		end

--invariant
--	path_starts_by_slash: path[1] = '/'

note
	copyright: "2011-2011, Eiffel Software and others"
	license: "Eiffel Forum License v2 (see http://www.eiffel.com/licensing/forum.txt)"
	source: "[
			Eiffel Software
			5949 Hollister Ave., Goleta, CA 93117 USA
			Telephone 805-685-1006, Fax 805-685-6869
			Website http://www.eiffel.com
			Customer support http://support.eiffel.com
		]"
end
