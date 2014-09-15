note
	description: "[
			This class is the link between WGI_SERVICE and WSF_SERVICE
			It makes a WSF_SERVICE callable from the WGI_ world.

		]"
	date: "$Date$"
	revision: "$Revision$"

class
	WSF_TO_WGI_SERVICE

inherit
	WGI_SERVICE

create
	make_from_service

feature {NONE}  -- Make

	make_from_service (a_service: like service)
			-- Make from WSF_SERVICE `a_service'
		do
			service := a_service
		end

	service: WSF_SERVICE
			-- Associated WSF_SERVICE

feature {WGI_CONNECTOR} -- Implementation: Execution

	execution (req: separate WGI_REQUEST; res: separate WGI_RESPONSE): separate WGI_REQUEST_EXECUTION
			-- Delegate the WGI processing to the WSF_SERVICE object
			-- <Precursor>
		local
			w_res: detachable WSF_RESPONSE
			w_req: detachable WSF_REQUEST
		do
			create w_res.make_from_wgi (res)
			create w_req.make_from_wgi (req)
			create {separate WSF_TO_WGI_REQUEST_EXECUTION} Result.make (agent execute, a_request, a_response)

			process_execution (service.execution (w_req, w_res))
			w_req.destroy
--		rescue
--			if w_res /= Void then
--				if not (w_res.status_committed or w_res.header_committed) then
--					w_res.set_status_code ({HTTP_STATUS_CODE}.internal_server_error)
--				end
--				w_res.flush
--			end
--			if w_req /= Void then
--				w_req.destroy
--			end
		end

	process_execution (a_execution: separate WSF_REQUEST_EXECUTION)
		do
			a_execution.execute
		end

note
	copyright: "2011-2014, Jocelyn Fiat, Javier Velilla, Olivier Ligot, Colin Adams, Eiffel Software and others"
	license: "Eiffel Forum License v2 (see http://www.eiffel.com/licensing/forum.txt)"
	source: "[
			Eiffel Software
			5949 Hollister Ave., Goleta, CA 93117 USA
			Telephone 805-685-1006, Fax 805-685-6869
			Website http://www.eiffel.com
			Customer support http://support.eiffel.com
		]"
end
