import cyberchefNode from "cyberchef-node";

async function runBake(input, recipe, options) {
    const parsedRecipe = JSON.parse(recipe);
    const parsedOptions = JSON.parse(options);

    try {
        const result = await cyberchefNode.bake(input, parsedRecipe, parsedOptions);
        console.log(result);
    }
    catch (error) {
        console.error('Error:', error);
    }
}

const input = process.argv[2];
const recipe = process.argv[3];
const options = process.argv[4];
runBake(input, recipe, options);