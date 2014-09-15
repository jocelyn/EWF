note
	description: "Summary description for {APPLICATION_REQUEST_EXECUTION}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	APPLICATION_REQUEST_EXECUTION

inherit
	WSF_REQUEST_EXECUTION

	SHARED_EXECUTION_ENVIRONMENT

create
	make

feature {NONE} -- Initialization

	make (req: WSF_REQUEST; res: WSF_RESPONSE)
		do
			request := req
			response := res
		end

feature -- Execution		

	execute
		local
			dt: DATE_TIME
			s: STRING
		do
			-- To send a response we need to setup, the status code and
			-- the response headers.
			create s.make_from_string ("Hello World")
			create dt.make_now_utc
			s.append_character (' ')
			s.append_character ('(')
			s.append (dt.out)
			s.append_character (')')

			if
				attached {WSF_STRING} request.query_parameter ("sleep") as p_sleep and then p_sleep.value.is_integer
			then
				s.append (" sleeping for " + p_sleep.value.to_integer.out + " seconds.")
				execution_environment.sleep (p_sleep.value.to_integer_64 * {INTEGER_64} 1_000_000_000)
			end

			response.put_header ({HTTP_STATUS_CODE}.ok, <<["Content-Type", "text/plain"], ["Content-Length", s.count.out]>>)
			response.put_string (s)
		end


end
