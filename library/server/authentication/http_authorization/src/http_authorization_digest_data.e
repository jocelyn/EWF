note
	description: "This class represents data from the Authorization header, for digest authentication. It also checks the integrity of this data."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	HTTP_AUTHORIZATION_DIGEST_DATA

inherit
	DEBUG_OUTPUT

create
	make

feature {NONE} -- Initialization

	make (a_realm, a_nonce, a_uri, a_response: READABLE_STRING_8; a_nc, a_cnonce, a_qop, a_opaque, a_algorithm: detachable READABLE_STRING_8)
			-- Initializie `current'.
			-- Also takes detachable arguments, in order to use the class invariant.
		require
			a_response_not_empty: not a_response.is_empty
		local
			qop_void, nc_void, cnonce_void: BOOLEAN
		do
			realm := a_realm
			nonce := a_nonce
			uri := a_uri
			response := a_response

			nc := a_nc
			cnonce := a_cnonce
			qop := a_qop
			opaque := a_opaque
			algorithm := a_algorithm
		end

feature -- Access: mandatory

	realm: READABLE_STRING_8 assign set_realm

	nonce: READABLE_STRING_8 assign set_nonce

	uri: READABLE_STRING_8 assign set_uri

	response: READABLE_STRING_8 assign set_response

feature -- Access

	nc: detachable READABLE_STRING_8 assign set_nc

	cnonce: detachable READABLE_STRING_8 assign set_cnonce

	qop: detachable READABLE_STRING_8 assign set_qop

	opaque: detachable READABLE_STRING_8 assign set_opaque

	algorithm: detachable READABLE_STRING_8 assign set_algorithm

feature -- Status report

	debug_output: STRING_32
			-- String that should be displayed in debugger to represent `Current'.
		do
			create Result.make_empty
			Result.append ("realm=")
			Result.append (realm)
			Result.append (" nonce=")
			Result.append (nonce)
			Result.append (" uri=")
			Result.append (uri)
			Result.append (" response=")
			Result.append (response)
		end

feature -- Access

	nc_as_integer: INTEGER
			-- Returns integer value of `nc'.
		require
			nc_attached: attached nc
		do
			if attached nc as l_nc then
				Result := l_nc.to_integer
			else
				check nc_not_attached: False end
			end
		end

feature -- Change

	set_realm (v: like realm)
			-- Set `realm' to `v'.
		do
			realm := v
		end

	set_nonce (v: like nonce)
			-- Set `nonce' to `v'.
		do
			nonce := v
		end

	set_nc (v: like nc)
			-- Set `nc' to `v'.
		require
		do
			nc := v
		end

	set_cnonce (v: like cnonce)
			-- Set `cnonce' to `v'.
		do
			cnonce := v
		end

	set_qop (v: like qop)
			-- Set `qop' to `v'.
		do
			qop := v
		end

	set_response (v: like response)
			-- Set `response' to `v'.
		require
			v_not_empty: not v.is_empty
		do
			response := v
		end

	set_opaque (v: like opaque)
			-- Set `opaque' to `v'.
		do
			opaque := v
		end

	set_uri (v: like uri)
			-- Set `uri' to `v'.
		do
			uri := v
		end

	set_algorithm (v: like algorithm)
			-- Set `algorithm' to `v'.
		do
			algorithm := v
		end

invariant
	response_not_empty: not response.is_empty
	supported_qop: attached qop as l_qop implies l_qop.is_case_insensitive_equal ("auth")
	supported_algorithm: attached algorithm as l_algorithm implies l_algorithm.is_case_insensitive_equal ("MD5")
	qop_not_void: ((qop /= Void) = ((cnonce /= Void and nc /= Void)))
	qop_void: ((qop = Void) = (cnonce = Void and nc = Void))
	nc_positive: attached nc as l_nc implies l_nc.to_integer > 0

end
