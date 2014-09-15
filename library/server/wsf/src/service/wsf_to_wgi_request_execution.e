note
	description: "Summary description for {WSF_TO_WGI_REQUEST_EXECUTION}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	WSF_TO_WGI_REQUEST_EXECUTION

inherit
	WGI_REQUEST_EXECUTION

create
	make

feature {NONE} -- Initialization

	make (req: like request; res: like response; a_service: WSF_SERVICE)
		do
			request := req
			response := res
			service := a_service
		end

feature -- Access

	service: separate WSF_SERVICE
			-- Associated WSF_SERVICE

feature -- Execution

	execute
		local
			w_res: detachable WSF_RESPONSE
			w_req: detachable WSF_REQUEST
		do
			create w_res.make_from_wgi (response)
			create w_req.make_from_wgi (request)

			process_execution (separate_service_execution (service, w_req, w_res))
			w_req.destroy
		rescue
			if w_res /= Void then
				if not (w_res.status_committed or w_res.header_committed) then
					w_res.set_status_code ({HTTP_STATUS_CODE}.internal_server_error)
				end
				w_res.flush
			end
			if w_req /= Void then
				w_req.destroy
			end
		end

	separate_service_execution (a_service: like service; req: WSF_REQUEST; res: WSF_RESPONSE): separate WSF_REQUEST_EXECUTION
		do
			Result := a_service.execution (req, res)
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
