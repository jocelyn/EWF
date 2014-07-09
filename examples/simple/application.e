note
	description : "simple application root class"
	date        : "$Date$"
	revision    : "$Revision$"

class
	APPLICATION

inherit
	WSF_DEFAULT_SERVICE
		redefine
			initialize
		end

	SHARED_EXECUTION_ENVIRONMENT

create
	make_and_launch

feature {NONE} -- Initialization

	initialize
			-- Initialize current service.
		do
			set_service_option ("port", 9090)
		end

feature -- Basic operations

	execute (req: WSF_REQUEST; res: WSF_RESPONSE)
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
				attached {WSF_STRING} req.query_parameter ("sleep") as p_sleep and then p_sleep.value.is_integer
			then
				s.append (" sleeping for " + p_sleep.value.to_integer.out + " seconds.")
				execution_environment.sleep (p_sleep.value.to_integer_64 * {INTEGER_64} 1_000_000_000)
			end

			res.put_header ({HTTP_STATUS_CODE}.ok, <<["Content-Type", "text/plain"], ["Content-Length", s.count.out]>>)
			res.put_string (s)
		end

end
