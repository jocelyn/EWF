note
	description: "Summary description for {HTTPD_DEBUG_FACILITIES}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

deferred class
	HTTPD_DEBUG_FACILITIES

feature {NONE} -- Output

	dbglog (m: READABLE_STRING_8)
		require
			not m.ends_with_general ("%N")
		do
			debug ("dbglog")
				print ("[EWF/DBG] " + m + "%N")
			end
		end


note
	copyright: "2011-2013, Javier Velilla, Jocelyn Fiat and others"
	license: "Eiffel Forum License v2 (see http://www.eiffel.com/licensing/forum.txt)"
end
