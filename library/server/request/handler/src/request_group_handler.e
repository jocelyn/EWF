note
	description: "Summary description for {REQUEST_GROUP_HANDLER}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	REQUEST_GROUP_HANDLER

inherit
	REQUEST_HANDLER

create
	make

feature {NONE} -- Initialization

	make (a_count: INTEGER)
		do
			description := "Request Group Handler"
			create handlers.make (a_count)
			initialize
		end

feature -- Access

	handlers: REQUEST_HANDLER_MANAGER
			-- Associated handlers

	authentication_required: BOOLEAN
		do
			Result := False
		end

feature -- Addition

	add_handler (p: STRING; r: REQUEST_HANDLER)
			-- Register handler `r'
--		require
--			valid_path: r.path.starts_with (path)
		do
			handlers.register (p, r)
		end

feature -- Execution

	execute_application (a_path: STRING; req: GW_REQUEST; res: GW_RESPONSE; a_format: detachable STRING_8; a_args: detachable STRING_8)
			-- Execute request handler with `a_format' ad `a_args'
		local
			l_path: STRING
			rq: detachable REQUEST_HANDLER
		do
			l_path := a_path
			rq := handlers.handler (req)
			if rq = Void then
				if attached handlers.smart_handler (req) as rq_info then
					rq := rq_info.handler
					l_path := rq_info.path
				end
			end
			if rq /= Void then
				check l_path.starts_with (a_path) end
				rq.execute (l_path, req, res)
			else
				execute_missing_application (req, res, a_format, a_args)
			end
		end

	execute_missing_application (req: GW_REQUEST; res: GW_RESPONSE; a_format: detachable STRING_8; a_args: detachable STRING_8)
		do
			res.write_header ({HTTP_STATUS_CODE}.not_acceptable, Void)
		end

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
