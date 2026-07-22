import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import express from "express";
import multer from "multer";

const app = express();

const PORT = Number(process.env.PORT || 3000);
const STORAGE_DIR = process.env.STORAGE_DIR || "/data/music";

const UPLOAD_USERNAME = process.env.UPLOAD_USERNAME || "admin";
const UPLOAD_PASSWORD = process.env.UPLOAD_PASSWORD;

if (!UPLOAD_PASSWORD) {
  console.warn(
    "警告：未设置 UPLOAD_PASSWORD，上传页面目前没有密码保护。"
  );
}

fs.mkdirSync(STORAGE_DIR, { recursive: true });

const allowedExtensions = new Set([
  ".mp3",
  ".m4a",
  ".aac",
  ".flac",
  ".wav",
  ".ogg",
  ".opus"
]);

const allowedMimeTypes = new Set([
  "audio/mpeg",
  "audio/mp3",
  "audio/mp4",
  "audio/x-m4a",
  "audio/aac",
  "audio/flac",
  "audio/x-flac",
  "audio/wav",
  "audio/x-wav",
  "audio/ogg",
  "audio/opus",
  "application/ogg",
  "application/octet-stream"
]);

function safeExtension(originalName) {
  const extension = path.extname(originalName).toLowerCase();

  if (!allowedExtensions.has(extension)) {
    return "";
  }

  return extension;
}

function basicAuth(req, res, next) {
  if (!UPLOAD_PASSWORD) {
    return next();
  }

  const authorization = req.headers.authorization || "";

  if (!authorization.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="MP3 Upload"');
    return res.status(401).send("需要登录");
  }

  let credentials;

  try {
    credentials = Buffer.from(
      authorization.slice("Basic ".length),
      "base64"
    ).toString("utf8");
  } catch {
    return res.status(401).send("登录信息无效");
  }

  const separatorIndex = credentials.indexOf(":");

  if (separatorIndex === -1) {
    return res.status(401).send("登录信息无效");
  }

  const username = credentials.slice(0, separatorIndex);
  const password = credentials.slice(separatorIndex + 1);

  const usernameBuffer = Buffer.from(username);
  const expectedUsernameBuffer = Buffer.from(UPLOAD_USERNAME);
  const passwordBuffer = Buffer.from(password);
  const expectedPasswordBuffer = Buffer.from(UPLOAD_PASSWORD);

  const usernameMatches =
    usernameBuffer.length === expectedUsernameBuffer.length &&
    crypto.timingSafeEqual(usernameBuffer, expectedUsernameBuffer);

  const passwordMatches =
    passwordBuffer.length === expectedPasswordBuffer.length &&
    crypto.timingSafeEqual(passwordBuffer, expectedPasswordBuffer);

  if (!usernameMatches || !passwordMatches) {
    res.setHeader("WWW-Authenticate", 'Basic realm="MP3 Upload"');
    return res.status(401).send("用户名或密码错误");
  }

  next();
}

const storage = multer.diskStorage({
  destination(req, file, callback) {
    callback(null, STORAGE_DIR);
  },

  filename(req, file, callback) {
    const extension = safeExtension(file.originalname);

    if (!extension) {
      return callback(new Error("不支持这种文件格式"));
    }

    const randomName = crypto.randomBytes(12).toString("hex");
    callback(null, `${randomName}${extension}`);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 100 * 1024 * 1024,
    files: 100
  },
  fileFilter(req, file, callback) {
    const extension = safeExtension(file.originalname);

    if (!extension) {
      return callback(new Error(`不支持的文件：${file.originalname}`));
    }

    if (
      file.mimetype &&
      !allowedMimeTypes.has(file.mimetype) &&
      !file.mimetype.startsWith("audio/")
    ) {
      return callback(new Error(`文件类型不正确：${file.originalname}`));
    }

    callback(null, true);
  }
});

function publicBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) {
    return process.env.PUBLIC_BASE_URL.replace(/\/+$/, "");
  }

  const forwardedProto = req.headers["x-forwarded-proto"];
  const protocol =
    typeof forwardedProto === "string"
      ? forwardedProto.split(",")[0]
      : req.protocol;

  return `${protocol}://${req.get("host")}`;
}

app.disable("x-powered-by");
app.set("trust proxy", true);

app.use(
  "/f",
  express.static(STORAGE_DIR, {
    fallthrough: false,
    index: false,
    acceptRanges: true,
    cacheControl: true,
    maxAge: "7d",
    immutable: false,
    setHeaders(res) {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("X-Content-Type-Options", "nosniff");
    }
  })
);

app.get("/", basicAuth, (req, res) => {
  res.sendFile(path.resolve("public/index.html"));
});

app.post(
  "/api/upload",
  basicAuth,
  upload.array("files", 100),
  (req, res) => {
    const files = req.files || [];
    const baseUrl = publicBaseUrl(req);

    const result = files.map((file) => ({
      originalName: file.originalname,
      storedName: file.filename,
      size: file.size,
      url: `${baseUrl}/f/${encodeURIComponent(file.filename)}`
    }));

    res.json({
      success: true,
      count: result.length,
      files: result
    });
  }
);

app.get("/api/files", basicAuth, async (req, res, next) => {
  try {
    const entries = await fs.promises.readdir(STORAGE_DIR, {
      withFileTypes: true
    });

    const baseUrl = publicBaseUrl(req);

    const files = await Promise.all(
      entries
        .filter((entry) => entry.isFile())
        .map(async (entry) => {
          const fullPath = path.join(STORAGE_DIR, entry.name);
          const stat = await fs.promises.stat(fullPath);

          return {
            name: entry.name,
            size: stat.size,
            modifiedAt: stat.mtime.toISOString(),
            url: `${baseUrl}/f/${encodeURIComponent(entry.name)}`
          };
        })
    );

    files.sort(
      (a, b) =>
        new Date(b.modifiedAt).getTime() -
        new Date(a.modifiedAt).getTime()
    );

    res.json({ files });
  } catch (error) {
    next(error);
  }
});

app.use((error, req, res, next) => {
  console.error(error);

  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({
        success: false,
        error: "有文件超过 100 MB"
      });
    }

    if (error.code === "LIMIT_FILE_COUNT") {
      return res.status(413).json({
        success: false,
        error: "一次最多上传 100 个文件"
      });
    }
  }

  res.status(400).json({
    success: false,
    error: error.message || "上传失败"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`服务器正在监听端口 ${PORT}`);
  console.log(`歌曲保存目录：${STORAGE_DIR}`);
});
