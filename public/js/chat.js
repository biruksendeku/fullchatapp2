const socket = io();

const msgs = document.getElementById('msgs');
const input = document.getElementById('message');
const btn1 = document.getElementById('btn1');
const btn2 = document.getElementById('btn2');

appendMsg('You Joined');
socket.emit('user-connection');

socket.on('handle-user-connection', (name) => {
	appendMsg(`${name} Joined`);
});

btn1.addEventListener('click', (e) => {
	e.preventDefault();
	const msg = input.value;
	appendMsg(`You: ${msg}`);
	msgs.scrollTop = msgs.scrollHeight;
	const data = {
		name: null,
		message: msg
	};
	socket.emit('send-message', data);
	input.value = '';
});

socket.on('handle-send-message', (data) => {
	appendMsg(`${data.name}: ${data.message}`);
});

btn2.addEventListener('click', (e) => {
	e.preventDefault();
	socket.emit('user-disconnection');
});

socket.on('handle-user-disconnection', (name) => {
	appendMsg(`${name} Disconnected`);
});

function appendMsg(message) {
	const newDiv = document.createElement('div');
	newDiv.textContent = message;
	msgs.appendChild(newDiv);
};
