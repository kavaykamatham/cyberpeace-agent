function extractUrl(text) {

    const regex =
        /(https?:\/\/[^\s]+)/g;

    const matches =
        text.match(regex);

    return matches ? matches : [];
}

module.exports = {
    extractUrl
};