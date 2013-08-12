note
	description : "Objects that ..."
	author      : "$Author$"
	date        : "$Date$"
	revision    : "$Revision$"

class
	GEWF

inherit
	SHARED_EXECUTION_ENVIRONMENT

create
	make

feature {NONE} -- Initialization

	make
			-- Initialize `Current'.
		local
			args: ARGUMENTS_32
			cfg: detachable READABLE_STRING_32
			i,n: INTEGER
			s: READABLE_STRING_32
		do
			set_installation_directory (Void) -- Set default
			set_output_directory (Void) -- Set default

			create args
			n := args.argument_count
			if n > 0 then
				from
					i := 1
				until
					i > n
				loop
					s := args.argument (i)
					if s.starts_with_general ("-") then
						if s.is_case_insensitive_equal_general ("--config") then
							i := i + 1
							cfg := safe_argument (args, i)
						elseif s.is_case_insensitive_equal_general ("--install-dir") then
							i := i + 1
							set_installation_directory (safe_argument (args, i))
						elseif s.is_case_insensitive_equal_general ("--output-dir") then
							i := i + 1
							set_output_directory (safe_argument (args, i))
						end
					else
						cfg := s
					end
					i := i + 1
				end
			end
			if cfg /= Void then
				if file_exists (cfg) then
					load_configuration (cfg)
				elseif across available_templates as t some t.item.same_string (cfg) end then
					build_interactive_configuration (templates_path.extended (cfg).appended_with_extension ("cfg"))
				end
			end
			execute
		end

feature -- Status

feature -- Access

	installation_path: PATH

	templates_path: PATH
		do
			Result := installation_path.extended ("template")
		end

	output_path: PATH

	available_templates: LIST [READABLE_STRING_32]
		local
			d: DIRECTORY
			s: READABLE_STRING_32
		do
			create d.make_with_path (templates_path)
			create {ARRAYED_LIST [READABLE_STRING_32]} Result.make (5)
			across
				d.entries as c
			loop
				if c.item.is_parent_symbol or c.item.is_current_symbol then
				elseif attached c.item.extension as ext and then ext.same_string_general ("cfg") then
					s := c.item.name
					Result.force (s.substring (1, s.count - 1 - ext.count))
				end
			end
		end

feature -- Change

	set_installation_directory (d: detachable READABLE_STRING_32)
		do
			if d = Void then
				installation_path := execution_environment.current_working_path
			else
				create installation_path.make_from_string (d)
			end
		end

	set_output_directory (d: detachable READABLE_STRING_32)
		do
			if d = Void then
				output_path := execution_environment.current_working_path
			else
				create output_path.make_from_string (d)
			end
		end

feature -- Query	

	config (k: READABLE_STRING_GENERAL): detachable READABLE_STRING_32
		do
			if attached {JSON_STRING} json_item (json, k) as js then
				Result := js.unescaped_string_32
			end
		end

	json_item (j: detachable JSON_VALUE; k: READABLE_STRING_GENERAL): detachable JSON_VALUE
		local
			l_keys: LIST [READABLE_STRING_GENERAL]
			v: detachable JSON_VALUE
			s: STRING_32
			js: JSON_STRING
		do
			if attached {JSON_OBJECT} j as jo then
				l_keys := k.split ('.')
				l_keys.start
				create js.make_json_from_string_32 (l_keys.item.as_readable_string_32)
				v := jo.item (js)
				l_keys.remove
				if l_keys.count > 0 then
					if v /= Void then
						create s.make (k.count)
						across
							l_keys as c
						loop
							s.append_string_general (c.item)
							s.append_character ('.')
						end
						s.remove_tail (1)
						Result := json_item (v, s)
					end
				else
					Result := v
				end
			end
		end

	load_configuration (fn: READABLE_STRING_GENERAL)
		local
			p: JSON_PARSER
			f: PLAIN_TEXT_FILE
			s: STRING
		do
			create s.make (1_024)

			create f.make_with_name (fn)
			if f.exists and then f.is_access_readable then
				f.open_read
				from
				until
					f.exhausted
				loop
					f.read_stream_thread_aware (1_024)
					s.append (f.last_string)
				end
				f.close
			end

			create p.make_parser (s)
			json := p.parse
		end

	build_interactive_configuration (fn: PATH)
		local
			p: JSON_PARSER
			f: PLAIN_TEXT_FILE
			s: STRING
			it: GEWF_JSON_ITERATOR
			vars: STRING_TABLE [READABLE_STRING_32]
		do
			create s.make (1_024)

			create f.make_with_path (fn)
			if f.exists and then f.is_access_readable then
				f.open_read
				from
				until
					f.exhausted
				loop
					f.read_stream_thread_aware (1_024)
					s.append (f.last_string)
				end
				f.close
			end

			create p.make_parser (s)
			json := p.parse
			if p.is_parsed and then attached json as j then
				create vars.make (0)
				create it.make (vars)
				j.accept (it)
				variables := vars
			end
		end

	json: detachable JSON_VALUE

	variables: detachable STRING_TABLE [READABLE_STRING_32]

feature -- Execution

	execute
		local
			tpl_name: READABLE_STRING_32
			vals: STRING_TABLE [READABLE_STRING_8]
			uuid_gen: UUID_GENERATOR
			vars: like variables
		do
			if attached config ("template") as s32 then
				create vals.make (5)

				tpl_name := s32
				create uuid_gen
				vals.force (uuid_gen.generate_uuid.out, "UUID")

				if
					attached config ("application.name") as appname
				then
					vals.force (appname.to_string_8, "appname")
				else
					vals.force ("application", "appname")
				end

				if
					attached config ("application.root_class") as approot
				then
					vals.force (approot.to_string_8, "APP_ROOT")
				else
					vals.force ("APPLICATION", "APP_ROOT")
				end

				vars := variables
				if vars /= Void and then not vars.is_empty then
					across
						vars as c
					loop
						if c.item.is_valid_as_string_8 then
							vals.force (c.item.as_string_8, c.key)
						end
					end
				end

				generate (tpl_name, vals)
			else
				io.error.put_string ("Error no template value! %N")
			end
		end

	generate (tpl: READABLE_STRING_32; vals: STRING_TABLE [READABLE_STRING_8])
		local
			gen: GEWF_GENERATOR
			p: PATH
			appname: detachable READABLE_STRING_GENERAL
		do
			p := templates_path.extended (tpl)
			appname := vals.item ("appname")
			if appname = Void then
				appname := "_generated"
			end
			create gen.make (p, create {PATH}.make_from_string (appname))
			gen.execute (vals)
		end

feature {NONE} -- Implementation

	safe_argument (args: ARGUMENTS_32; i: INTEGER): detachable IMMUTABLE_STRING_32
		do
			if 1 <= i and i <= args.argument_count then
				Result := args.argument (i)
			end
		end

	file_exists (fn: READABLE_STRING_GENERAL): BOOLEAN
		local
			f: RAW_FILE
		do
			create f.make_with_name (fn)
			Result := f.exists
		end

invariant
--	invariant_clause: True

note
	copyright: "2011-2013, Jocelyn Fiat, Javier Velilla, Olivier Ligot, Eiffel Software and others"
	license: "Eiffel Forum License v2 (see http://www.eiffel.com/licensing/forum.txt)"
	source: "[
			Eiffel Software
			5949 Hollister Ave., Goleta, CA 93117 USA
			Telephone 805-685-1006, Fax 805-685-6869
			Website http://www.eiffel.com
			Customer support http://support.eiffel.com
		]"
end
