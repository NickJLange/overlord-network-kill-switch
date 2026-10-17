module.exports = {
    uiHost: '0.0.0.0',
    uiPort: 1880,
    // Exercise the real flows without exposing an unauthenticated editor.
    httpAdminRoot: false,
    disableEditor: true,
    flowFile: '/data/flows.json',
    credentialSecret: false,
};
