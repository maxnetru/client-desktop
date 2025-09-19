import fs from "fs";

export const getAuthData = () => {
    return fs.existsSync("auth-data.json") ? JSON.parse(fs.readFileSync("auth-data.json", "utf-8")) : {};
}
export const setAuthData = (id: string, token: string) => {
    fs.writeFileSync("auth-data.json", JSON.stringify({ id, token }));
}