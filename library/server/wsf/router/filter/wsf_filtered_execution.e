note
	description: "Summary description for {WSF_FILTERED_EXECUTION}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

deferred class
	WSF_FILTERED_EXECUTION

inherit
	WSF_EXECUTION
		redefine
			initialize
		end

	WSF_FILTERED_EXECUTOR
		rename
			initialize as initialize_executor,
			execute as process_execution
		end

feature {NONE} -- Initialization

	initialize
		do
			Precursor {WSF_EXECUTION}
			initialize_executor
		end

feature -- Execution

	execute
			-- Dispatch the request
			-- and if handler is not found, execute the default procedure `execute_default'.
		do
			process_execution (request, response)
		end

;note
	copyright: "2011-2015, Jocelyn Fiat, Javier Velilla, Olivier Ligot, Colin Adams, Eiffel Software and others"
	license: "Eiffel Forum License v2 (see http://www.eiffel.com/licensing/forum.txt)"
	source: "[
			Eiffel Software
			5949 Hollister Ave., Goleta, CA 93117 USA
			Telephone 805-685-1006, Fax 805-685-6869
			Website http://www.eiffel.com
			Customer support http://support.eiffel.com
		]"
end
