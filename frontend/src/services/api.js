const API_URL = "http://localhost:5000";

export const checkAPI = async () => {
    const response = await fetch(API_URL);
    const data = await response.json();
    return data;
};