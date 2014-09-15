note
	description: "[
		Inherit from this class to implement the main entry of your web service
		You just need to implement `execute', get data from the request `req'
		and write the response in `res'
	]"
	date: "$Date$"
	revision: "$Revision$"

deferred class
	WSF_SERVICE

inherit
	WSF_REQUEST_EXECUTION_FACTORY

feature -- Execution

--	execution (a_request: WSF_REQUEST; a_response: WSF_RESPONSE): separate WSF_REQUEST_EXECUTION
--			-- Execution for the request `a_request' and response `a_response'.
--		deferred
--		end

--		do
--			create {WSF_REQUEST_AGENT_EXECUTION} Result.make (agent execute, a_request, a_response)
--		end

--feature {NONE} -- Execution: restricted.

--	execute (req: WSF_REQUEST; res: WSF_RESPONSE)
--			-- Execute the request
--			-- See `req.input' for input stream
--    		--     `req.meta_variables' for the CGI meta variable
--			-- and `res' for output buffer
--		deferred
--		end

feature -- Conversion

	to_wgi_service: WGI_SERVICE
			-- Adapt Current WSF Service to plug into WGI component
		do
			create {WSF_TO_WGI_SERVICE} Result.make_from_service (Current)
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
