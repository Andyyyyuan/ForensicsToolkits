from pydantic import BaseModel


class FileUploadResponse(BaseModel):
    file_id: str
    original_name: str
    size: int
    created_at: str
