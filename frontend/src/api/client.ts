import axios from 'axios'

export const apiBaseUrl = import.meta.env.VITE_API_BASE_URL || '/api/v1'

export const api = axios.create({
  baseURL: apiBaseUrl,
  timeout: 60000,
})
