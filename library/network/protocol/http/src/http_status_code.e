note
	description: "[
			Status code constants pertaining to the HTTP protocol
			See http://en.wikipedia.org/wiki/List_of_HTTP_status_codes
		]"
	legal: "See notice at end of class."
	status: "See notice at end of class."
	date: "$Date$"
	revision: "$Revision$"

class
	HTTP_STATUS_CODE

feature -- 1xx : Informational

	continue: NATURAL 				= 100
	switching_protocols: NATURAL 	= 101
	processing: NATURAL 			= 102 	-- WebDAV RFC 2518
	ie7_request_uri_too_long: NATURAL 	= 122 	-- non standard, IE7 only

feature -- 2xx : Success

	ok: NATURAL						= 200
	created: NATURAL 				= 201
	accepted: NATURAL 				= 202
	nonauthoritative_info: NATURAL 	= 203
	no_content: NATURAL 			= 204
	reset_content: NATURAL 			= 205
	partial_content: NATURAL 		= 206
	multistatus: NATURAL 			= 207	-- WebDAV RFC 4918
	im_used: NATURAL 				= 226	-- RFC 4918

feature -- 3xx : Redirection

	multiple_choices: NATURAL		= 300
	moved_permanently: NATURAL 		= 301
	found: NATURAL 					= 302
	see_other: NATURAL 				= 303
	not_modified: NATURAL 			= 304
	use_proxy: NATURAL 				= 305
	switch_proxy: NATURAL 			= 306
	temp_redirect: NATURAL 			= 307

feature -- 4xx : Client Error

	bad_request: NATURAL 					= 400
	unauthorized: NATURAL 					= 401
	payment_required: NATURAL 				= 402
	forbidden: NATURAL 						= 403
	not_found: NATURAL 						= 404
	method_not_allowed: NATURAL 			= 405
	not_acceptable: NATURAL 				= 406
	proxy_auth_required: NATURAL 			= 407
	request_timeout: NATURAL 				= 408
	conflict: NATURAL 						= 409
	gone: NATURAL 							= 410
	length_required: NATURAL 				= 411
	precondition_failed: NATURAL 			= 412
	request_entity_too_large: NATURAL 		= 413
	request_uri_too_long: NATURAL 			= 414
	unsupported_media_type: NATURAL 		= 415
	request_range_not_satisfiable: NATURAL 	= 416
	expectation_failed: NATURAL 			= 417
	teapot: NATURAL							= 418

feature -- 4xx : Client Error : WebDAV errors

	too_many_connections: NATURAL			= 421
	unprocessable_entity: NATURAL 			= 422
	locked: NATURAL 						= 423
	failed_dependency: NATURAL 				= 424
	unordered_collection: NATURAL 			= 425

	upgrade_required: NATURAL 				= 426
	no_response: NATURAL 					= 444
	retry_with: NATURAL 					= 449
	blocked_parental: NATURAL 				= 450
	client_closed_request: NATURAL 			= 499

feature -- 5xx : Server Error

	internal_server_error: NATURAL			= 500
	not_implemented: NATURAL 				= 501
	bad_gateway: NATURAL 					= 502
	service_unavailable: NATURAL 			= 503
	gateway_timeout: NATURAL 				= 504
	http_version_not_supported: NATURAL 	= 505
	variant_also_negotiates: NATURAL 		= 506
	insufficient_storage: NATURAL 			= 507	-- WebDAV RFC 4918

	bandwidth_limit_exceeded: NATURAL		= 509
	not_extended: NATURAL 					= 510

	user_access_denied: NATURAL 			= 530

note
	copyright: "2011-2012, Jocelyn Fiat, Eiffel Software and others"
	license: "Eiffel Forum License v2 (see http://www.eiffel.com/licensing/forum.txt)"
	source: "[
			Eiffel Software
			5949 Hollister Ave., Goleta, CA 93117 USA
			Telephone 805-685-1006, Fax 805-685-6869
			Website http://www.eiffel.com
			Customer support http://support.eiffel.com
		]"
end
