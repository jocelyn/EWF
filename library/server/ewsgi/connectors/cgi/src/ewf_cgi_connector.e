note
	description: "Summary description for {EWF_CGI_CONNECTOR}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	EWF_CGI_CONNECTOR

inherit
	WGI_CONNECTOR

create
	make

feature -- Execution

	launch
		local
			req: WGI_REQUEST_FROM_TABLE
			res: detachable WGI_RESPONSE_STREAM_BUFFER
			rescued: BOOLEAN
		do
			if not rescued then
				create req.make ((create {EXECUTION_ENVIRONMENT}).starting_environment_variables, create {EWF_CGI_INPUT_STREAM}.make)
				create res.make (create {EWF_CGI_OUTPUT_STREAM}.make)
				application.execute (req, res)
			else
				if attached (create {EXCEPTION_MANAGER}).last_exception as e and then attached e.exception_trace as l_trace then
					if res /= Void then
						if not res.status_is_set then
							res.write_header ({HTTP_STATUS_CODE}.internal_server_error, Void)
						end
						if res.message_writable then
							res.write_string ("<pre>" + l_trace + "</pre>")
						end
					end
				end
			end
		rescue
			rescued := True
			retry
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
