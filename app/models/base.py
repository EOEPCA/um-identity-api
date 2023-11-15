from pydantic import BaseModel, ConfigDict


class APIBaseModel(BaseModel):
    model_config = ConfigDict(extra='forbid', use_enum_values=True)
    def model_dump(self, exclude_none=True, **kwargs):
        return super().model_dump(exclude_none=exclude_none, **kwargs)