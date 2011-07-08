note
	description: "Summary description for {GW_APPLICATION}."
	legal: "See notice at end of class."
	status: "See notice at end of class."
	date: "$Date$"
	revision: "$Revision$"

deferred class
	GW_APPLICATION

feature -- Execution

	process (env: GW_ENVIRONMENT; a_input: GW_INPUT_STREAM; a_output: GW_OUTPUT_STREAM)
		do
			execute (new_request_context (env, a_input, a_output))
		end

	execute (ctx: GW_REQUEST_CONTEXT)
			-- Execute the request
		deferred
		end

feature -- Factory

	new_request_context (env: GW_ENVIRONMENT; a_input: GW_INPUT_STREAM; a_output: GW_OUTPUT_STREAM): GW_REQUEST_CONTEXT
		deferred
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
