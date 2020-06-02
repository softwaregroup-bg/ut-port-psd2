const Client = require('openapi-client-axios').default;
const cache = {};

module.exports = async function(params, method, path) {
    const [provider, api, operation] = method.split('.');
    let fn = cache[method];
    if (!fn) {
        const client = new Client({
            definition: `${path}/${provider}/${api}.yaml`,
            validate: false
        });
        client.createAxiosInstance = () => {};
        await client.init();
        fn = () => client.getRequestConfigForOperation(operation, [params]);
        cache[method] = fn;
    }
    return fn();
};
