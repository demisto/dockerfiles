const cyberchefNode = require("cyberchef-node");

async function runMagic(input, args = "{}") {
    const parsedArgs = JSON.parse(args);

    try {
        const result = await cyberchefNode.magic(input, parsedArgs);
        console.log(result);
    }
    catch (error) {
        console.error('Error:', error);
    }
}

const input = process.argv[2];
const args = process.argv[3];
runMagic(input, args);