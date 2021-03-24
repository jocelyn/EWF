note
	description : "simple application execution"
	date        : "$Date$"
	revision    : "$Revision$"

class
	APPLICATION_EXECUTION

inherit
	WSF_WEBSOCKET_EXECUTION

	WEB_SOCKET_EVENT_I
		redefine
			on_timer
		end

create
	make

feature -- Basic operations

	execute
		local
			s: STRING
			dt: HTTP_DATE
 		do
 			-- To send a response we need to setup, the status code and
 			-- the response headers.
			if request.path_info.same_string_general ("/favicon.ico") then
				response.put_header ({HTTP_STATUS_CODE}.not_found, <<["Content-Length", "0"]>>)
			else
				if request.path_info.same_string_general ("/app") then
					if attached {WSF_STRING} request.form_parameter ("user") as l_user then
						s := websocket_app_html (l_user.value, request.server_name, request.server_port)
					else
						s := websocket_app_welcome_html (request.server_name, request.server_port)
					end
				else
		 			s := "Hello World!"
					create dt.make_now_utc
					s.append (" (UTC time is " + dt.rfc850_string + ").")
					s.append ("<p><a href=%"/app%">Websocket demo</a></p>")
				end
				response.put_header ({HTTP_STATUS_CODE}.ok, <<["Content-Type", "text/html"], ["Content-Length", s.count.out]>>)
				response.set_status_code ({HTTP_STATUS_CODE}.ok)
				response.header.put_content_type_text_html
				response.header.put_content_length (s.count)
				if request.is_keep_alive_http_connection then
					response.header.put_connection_keep_alive
				end
				response.put_string (s)
			end
		end

feature -- Common chat

	chat_room: separate ROOM
		once ("PROCESS")
			create Result.make (5)
		end

	register_user (r: separate ROOM; u: ROOM_USER)
		do
			r.register_user (u)
		end

	update_user_name (r: separate ROOM; u: ROOM_USER)
		do
			r.update_user_name (u.id, u.name)
		end

	unregister_user (r: separate ROOM; u: ROOM_USER)
		do
			r.unregister_user (u.id)
		end

	forward_message (r: separate ROOM; msg: READABLE_STRING_8)
		local
			m: STRING_32
		do
			if attached last_user as u then
				create m.make (msg.count + 20)
				m.append_string_general ("@")
				m.append_string (u.name_or_id)
				m.append_string_general ("> %N")
				m.append_string_general (msg)
				r.send_message_to_others (m, u)
			end
		end

	looping: BOOLEAN

	looping_index: INTEGER

	last_user: detachable ROOM_USER

	variables: detachable STRING_TABLE [READABLE_STRING_32]

	variable (a_key: READABLE_STRING_GENERAL): detachable READABLE_STRING_32
		do
			if attached variables as vars then
				Result := vars [a_key]
			end
		end

	set_variable (a_key: READABLE_STRING_GENERAL; a_value: READABLE_STRING_GENERAL)
		local
			vars: like variables
		do
			vars := variables
			if vars = Void then
				create vars.make (1)
				variables := vars
			end
			vars [a_key] := a_value
		end

feature -- Websocket execution

	new_websocket_handler (ws: WEB_SOCKET): WEB_SOCKET_HANDLER
		do
			create Result.make (ws, Current)
		end

feature -- Websocket execution

	on_open (ws: WEB_SOCKET)
		local
			u: ROOM_USER
			l_name: STRING_32
			i: INTEGER
		do
			initialize_commands
			set_timer_delay (1) -- Every 1 second.

			ws.put_error ("Connecting")
			ws.send (Text_frame, "Hello, this is a simple demo with Websocket using Eiffel. (/help for more information).%N")

			if attached {WSF_STRING} request.form_parameter ("user") as p_user then
				l_name := p_user.value
			elseif attached variable ("user") as l_user then
				l_name := l_user
			else
				l_name := request.path_info.twin
				i := l_name.substring_index ("/user=", 1)
				if i > 0 then
					i := i + 5 -- skip "/user="
					l_name.remove_head (i)
					i := l_name.index_of (';', 1)
					if i > 0 then
						l_name.keep_head (i - 1)
					end
				else
					l_name := Void
				end
			end
			if l_name /= Void then
				create u.make_with_name (ws, l_name)
			else
				create u.make (ws)
			end

			last_user := u

			register_user (chat_room, u)
		end

	on_binary (ws: WEB_SOCKET; a_message: READABLE_STRING_8)
		do
			ws.send (Binary_frame, a_message)
		end

	on_text (ws: WEB_SOCKET; a_message: READABLE_STRING_8)
		local
			i: INTEGER
			cmd_name: READABLE_STRING_8
			arg: STRING_8
		do
			if a_message.starts_with_general ("/") then
				from
					i := 1
				until
					i >= a_message.count or else a_message[i + 1].is_space
				loop
					i := i + 1
				end
				cmd_name := a_message.substring (2, i)
				if attached command (cmd_name) as cmd then
					arg := a_message.substring (i + 1, a_message.count).to_string_8
					arg.left_adjust
					cmd (ws, arg)
				elseif a_message.same_string_general ("/help") then
					on_help_command (ws, Void)
				else
					ws.send (Text_frame, "Error: unknown command '/" + cmd_name + "'!%N")
				end
			else
					-- Echo the message for testing.
				forward_message (chat_room, a_message)
			end
		end

	on_close (ws: WEB_SOCKET)
			-- Called after the WebSocket connection is closed.
		do
			ws.put_error ("Connection closed")
			if attached last_user as u then
				unregister_user (chat_room, u)
			end
			last_user := Void
			variables := Void
		end

	on_timer (ws: WEB_SOCKET)
			-- <Precursor>.
			-- If ever the file ".stop" exists, stop gracefully the connection.
		local
			fut: FILE_UTILITIES
			f: RAW_FILE
		do
			if fut.file_exists (".stop") then
				ws.send_text ("End of the communication ...%N")
				ws.send_connection_close ("")
				create f.make_with_name (".stop")
				f.delete
			elseif looping then
				looping_index := looping_index + 1
				ws.send_text ("[" + looping_index.out + "]")
			end
		end

feature -- Command

	initialize_commands
		do
			register_command (agent on_set_command, "set", Void)
			register_command (agent on_help_command, "help", "Display this help.")
			register_command (agent on_time_command, "time", "Return the server UTC time.")
			register_command (agent on_shutdown_command, "shutdown", "Shutdown the service (ends the websocket).")
			register_command (agent on_loop_command, "loop", "start/stop looping echo.")
		end

	register_command (a_cmd: attached like command; a_name: READABLE_STRING_8; a_description: detachable READABLE_STRING_8)
		local
			tb: like commands
		do
			tb := commands
			if tb = Void then
				create tb.make_caseless (1)
				commands := tb
			end
			tb.force ([a_cmd, a_name, a_description], a_name)
		end

	commands: detachable STRING_TABLE [TUPLE [cmd: attached like command; name: READABLE_STRING_8; description: detachable READABLE_STRING_8]]

	command (a_name: READABLE_STRING_GENERAL): detachable PROCEDURE [TUPLE [ws: WEB_SOCKET; args: detachable READABLE_STRING_GENERAL]]
		do
			if
				attached commands as tb and then
				attached tb.item (a_name) as d
			then
				Result := d.cmd
			end
		end

	on_help_command (ws: WEB_SOCKET; args: detachable READABLE_STRING_GENERAL)
		local
			s: STRING
		do
			create s.make_from_string ("Help: available commands:%N<ul>")
			if attached commands as tb then
				across
					tb as ic
				loop
					if attached ic.item.description as desc then
						s.append ("<li> /")
						s.append (ic.item.name)
						s.append (" : ")
						s.append (desc)
						s.append ("</li>%N")
					end
				end
			end
			s.append ("</ul>")
			ws.send_text (s)
		end

	on_set_command (ws: WEB_SOCKET; args: detachable READABLE_STRING_GENERAL)
		local
			v: READABLE_STRING_GENERAL
		do
			if
				args /= Void and then
				args.starts_with ("user=")
			then
				v := args.substring (6, args.count)
				set_variable ("user", v)
				if attached last_user as u then
					if not u.name_or_id.same_string_general (v) then
						u.set_name (v)
						update_user_name (chat_room, u)
					end
				end
			end
		end

	on_time_command (ws: WEB_SOCKET; args: detachable READABLE_STRING_GENERAL)
		do
			ws.send_text ("Server time is " + (create {HTTP_DATE}.make_now_utc).string)
		end

	on_loop_command (ws: WEB_SOCKET; args: detachable READABLE_STRING_GENERAL)
		do
			if looping then
				ws.send_text ("Stop looping")
				set_timer_delay (1)
			else
				ws.send_text ("Start looping")
				set_timer_delay (5)
			end
			looping_index := 0
			looping := not looping
		end

	on_shutdown_command (ws: WEB_SOCKET; args: detachable READABLE_STRING_GENERAL)
		local
			f: RAW_FILE
		do
			ws.send_text ("Active websockets will end soon.%N")
			create f.make_create_read_write (".stop")
			f.put_string ("stop%N")
			f.close
		end

feature -- HTML Resource	

	websocket_app_welcome_html (a_host: READABLE_STRING_8; a_port: INTEGER): STRING
		do
			Result := "[
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<style type="text/css">
body {font-family:Arial, Helvetica, sans-serif;}
#container { border:5px solid grey; width:800px; margin:0 auto; padding:10px; }
</style>
<title>WebSockets Client</title>
</head>
<body>

  <div id="wrapper">
  	<div id="container">
    	<h1>WebSockets Client</h1>
    	<form action="#" method="post" id="user_name">
    		<input type="text" name="user" placeholder="Enter your pseudo" id="user"/>
    		<input type="submit" value="Enter"/>
		</form>
	</div>
  </div>
</body>
</html>
			]"
			Result.replace_substring_all ("##HOSTNAME##", a_host)
			Result.replace_substring_all ("##PORTNUMBER##", a_port.out)
			if request.is_https then
				Result.replace_substring_all ("##HTTPSCHEME##", "https")
				Result.replace_substring_all ("##WSSCHEME##", "wss")
			else
				Result.replace_substring_all ("##HTTPSCHEME##", "http")
				Result.replace_substring_all ("##WSSCHEME##", "ws")
			end
		end


	websocket_app_html (a_pseudo: READABLE_STRING_32; a_host: READABLE_STRING_8; a_port: INTEGER): STRING
		do
			Result := "[
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<script src="##HTTPSCHEME##://ajax.googleapis.com/ajax/libs/jquery/1.4.2/jquery.min.js"></script>
<script type="text/javascript">
$(document).ready(function() {

	var socket;

	function connect(username){
			var host = "##WSSCHEME##://##HOSTNAME##:##PORTNUMBER##/app/user=" + username;
			try{

				socket = new WebSocket(host);
				message('<p class="event">Socket Status: '+socket.readyState);
				socket.onopen = function(){
						message('<p class="event">Socket Status: '+socket.readyState+' (open)');
					}
				socket.onmessage = function(msg){
						message('<p class="message">Received: '+msg.data);
					}
				socket.onclose = function(){
						message('<p class="event">Socket Status: '+socket.readyState+' (Closed)');
					}
			} catch(exception){
				message('<p>Error'+exception);
			}
	}

	function send(){
		var text = $('#text').val();
		if(text==""){
			message('<p class="warning">Please enter a message');
			return ;
		}
		try{
			socket.send(text);
			message('<p class="event">Sent: '+text)
		} catch(exception){
			message('<p class="warning">');
		}
		$('#text').val("");
	}

	function message(msg){
		$('#chatLog').append(msg+'</p>');
	}//End message()

	$('#text').keypress(function(event) {
		  if (event.keyCode == '13') {
			 send();
		   }
	});

	$('#disconnect').click(function(){
		socket.close();
	});
	$('#time').click(function(){
		socket.send("/time");
	});
	$('#help').click(function(){
		socket.send("/help");
	});
	$('#loop').click(function(){
		socket.send("/loop");
	});
	$('#setname').click(function(){
		socket.send("/set user=" + $('#username').val());
	});

	if (!("WebSocket" in window)){
		$('#chatLog, input, button, #examples').fadeOut("fast");
		$('<p>Oh no, you need a browser that supports WebSockets. How about <a href="http://www.google.com/chrome">Google Chrome</a>?</p>').appendTo('#container');
	}else{
		//The user has WebSockets
		var username = $('#username').val();
		if(username==""){
			message('<p class="warning">Missing Username');
			return ;
		}		
		connect(username);
	}

});
</script>
<style type="text/css">
body {font-family:Arial, Helvetica, sans-serif;}
#container { border:5px solid grey; width:800px; margin:0 auto; padding:10px; }
#chatLog { padding:5px; border:1px solid black; }
#chatLog p {margin: 0;}
div.actions {margin: 1rem 0 0 0;}
.event {color:#999;}
.warning { font-weight:bold; color:#CCC; }
</style>
<title>WebSockets Client</title>
</head>
<body>
  <div id="wrapper">
  	<div id="container">
    	<h1>WebSockets Client</h1>
    	<p>User <strong>##USERNAME##</strong></p>
        <div id="chatLog"></div>
        <div class="actions">
    	<input id="text" type="text" size="60"/>
        <button id="disconnect">Disconnect</button>
        <button id="help">Help</button>
        </div>
        <div class="actions">
        <input id="username" type="text" value="##USERNAME##" size="20"/>
        <button id="setname">Set Name</button>
        </div>
        <div class="actions">
        <button id="time">Get Time</button>
        <button id="loop">Loop on/off</button>
        </div>
	</div>
  </div>
</body>
</html>
			]"
			Result.replace_substring_all ("##USERNAME##", {UTF_CONVERTER}.utf_32_string_to_utf_8_string_8 (a_pseudo))
			Result.replace_substring_all ("##HOSTNAME##", a_host)
			Result.replace_substring_all ("##PORTNUMBER##", a_port.out)
			if request.is_https then
				Result.replace_substring_all ("##HTTPSCHEME##", "https")
				Result.replace_substring_all ("##WSSCHEME##", "wss")
			else
				Result.replace_substring_all ("##HTTPSCHEME##", "http")
				Result.replace_substring_all ("##WSSCHEME##", "ws")
			end
		end

end
