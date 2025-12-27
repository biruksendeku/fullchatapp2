const express = require('express');
const { User, Brt } = require('./models/userStuff');

const app = express();
const port = 3000;

async function loadAllUsers() {
	const users = await User.find({});
	console.log('Users', users);
};
loadAllUsers();

async function loadAllBrts() {
	const brts = await Brt.find({});
	console.log('Brts: ', brts);
};
loadAllBrts();

app.delete('/user/:id', async (req, res) => {
	await User.findByIdAndDelete(req.params.id)
	.then(() => {
		res.status(200).send('Deleted Successfully');
	})
	.catch((err) => {
		res.status(400).send('Failed to Delete');
	});
});

app.listen(port, () => {
	console.log(`Server listening on port ${port}...`);
});
