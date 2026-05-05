/* eslint-disable no-console -- used for error logging */
import { type TUploadFileConfig, type TUploadFileResponse } from "@/types/storage";

export class StorageAPI {
  private appUrl: string;
  private environmentId: string;

  constructor(appUrl: string, environmentId: string) {
    this.appUrl = appUrl;
    this.environmentId = environmentId;
  }

  async uploadFile(
    file: {
      type: string;
      name: string;
      base64: string;
    },
    { allowedFileExtensions, surveyId }: TUploadFileConfig | undefined = {}
  ): Promise<string> {
    if (!file.name || !file.type || !file.base64) {
      throw new Error(`Invalid file object`);
    }

    const payload = {
      fileName: file.name,
      fileType: file.type,
      allowedFileExtensions,
      surveyId,
    };

    const response = await fetch(`${this.appUrl}/api/v1/client/${this.environmentId}/storage`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`Upload failed with status: ${String(response.status)}`);
    }

    const json = (await response.json()) as TUploadFileResponse;

    const { data } = json;

    const { signedUrl, fileUrl, signingData, presignedFields, updatedFileName } = data;

    let localUploadDetails: Record<string, string> = {};

    if (signingData) {
      const { signature, timestamp, uuid } = signingData;

      localUploadDetails = {
        fileType: file.type,
        fileName: encodeURIComponent(updatedFileName),
        surveyId: surveyId ?? "",
        signature,
        timestamp: String(timestamp),
        uuid,
      };
    }

    const formData: Record<string, string> = {};
    const formDataForS3 = new FormData();

    if (presignedFields) {
      Object.keys(presignedFields).forEach((key) => {
        formDataForS3.append(key, presignedFields[key]);
      });

      try {
        const buffer = Buffer.from(file.base64.split(",")[1], "base64");
        const blob = new Blob([buffer], { type: file.type });

        formDataForS3.append("file", blob);
      } catch (buffErr) {
        console.error({ buffErr });

        throw new Error("Error uploading file");
      }
    }

    formData.fileBase64String = file.base64;

    let uploadResponse: Response = {} as Response;

    const signedUrlCopy = signedUrl.replace("http://localhost:3000", this.appUrl);

    // binarybeachio: three upload paths — see comment in
    // apps/web/app/lib/fileUpload.ts. Server-side R2-friendly path
    // returns neither presignedFields nor signingData → presigned PUT.
    try {
      if (presignedFields) {
        uploadResponse = await fetch(signedUrlCopy, {
          method: "POST",
          body: formDataForS3,
        });
      } else if (signingData) {
        uploadResponse = await fetch(signedUrlCopy, {
          method: "POST",
          body: JSON.stringify({
            ...formData,
            ...localUploadDetails,
          }),
        });
      } else {
        const buffer = Buffer.from(file.base64.split(",")[1], "base64");
        const blob = new Blob([buffer], { type: file.type });
        uploadResponse = await fetch(signedUrlCopy, {
          method: "PUT",
          headers: { "Content-Type": file.type },
          body: blob,
        });
      }
    } catch (err) {
      console.error("Error uploading file", err);
    }

    if (!uploadResponse.ok) {
      // if local storage is used, we'll use the json response:
      if (signingData) {
        const uploadJson = (await uploadResponse.json()) as { message: string };
        const error = new Error(uploadJson.message);
        error.name = "FileTooLargeError";
        throw error;
      }

      // if s3 is used, we'll use the text response:
      const errorText = await uploadResponse.text();
      if (presignedFields && errorText.includes("EntityTooLarge")) {
        const error = new Error("File size exceeds the size limit for your plan");
        error.name = "FileTooLargeError";
        throw error;
      }

      throw new Error(`Upload failed with status: ${String(uploadResponse.status)}`);
    }

    return fileUrl;
  }
}
