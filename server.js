import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import express from "express";
import multer from "multer";
import Database from "better-sqlite3";

const app = express();

const PORT = Number(process.env.PORT || 3000);
const STORAGE_DIR = process.env.STORAGE_DIR || "/data/music";

const UPLOAD_USERNAME = process.env.UPLOAD_USERNAME || "admin";
const UPLOAD_PASSWORD = process.env.UPLOAD_PASSWORD;

function normalizeOriginalName(name) {
  const decoded = Buffer.from(name, "latin1").toString("utf8");

  if (decoded.includes("\uFFFD")) {
    return name;
  }

  const roundTrip = Buffer.from(decoded, "utf8").toString("latin1");
  return roundTrip === name ? decoded : name;
}

if (!UPLOAD_PASSWORD) {
  console.warn(
    "警告：未设置 UPLOAD_PASSWORD，上传页面目前没有密码保护。"
  );
}

fs.mkdirSync(STORAGE_DIR, { recursive: true });

const db = new Database(
  path.join(STORAGE_DIR, "music.db")
);

db.exec(`
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  original_name TEXT NOT NULL,
  stored_name TEXT NOT NULL UNIQUE,
  url TEXT NOT NULL,
  size INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
`);

const repairFileRecords = db.transaction(() => {
  const rows = db.prepare(`
    SELECT id, original_name, stored_name
    FROM files
    ORDER BY id DESC
  `).all();
  const updateName = db.prepare(`
    UPDATE files
    SET original_name = ?
    WHERE id = ?
  `);
  const deleteRecord = db.prepare(`
    DELETE FROM files
    WHERE id = ?
  `);
  const seenNames = new Set();

  for (const row of rows) {
    const originalName = normalizeOriginalName(row.original_name);

    if (seenNames.has(originalName)) {
      deleteRecord.run(row.id);

      try {
        fs.unlinkSync(path.join(STORAGE_DIR, row.stored_name));
      } catch (error) {
        if (error.code !== "ENOENT") {
          throw error;
        }
      }

      continue;
    }

    seenNames.add(originalName);

    if (originalName !== row.original_name) {
      updateName.run(originalName, row.id);
    }
  }
});

repairFileRecords();

db.exec(`
CREATE UNIQUE INDEX IF NOT EXISTS files_original_name_unique
ON files (original_name)
`);

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

    const insertFile = db.prepare(`
      INSERT INTO files
        (original_name, stored_name, url, size)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(original_name) DO NOTHING
    `);
    const findFile = db.prepare(`
      SELECT
        original_name AS originalName,
        stored_name AS storedName,
        size,
        url
      FROM files
      WHERE original_name = ?
    `);

    const insertFiles = db.transaction((uploadedFiles) =>
      uploadedFiles.map((file) => {
        const originalName = normalizeOriginalName(file.originalname);
        const url =
          `${baseUrl}/f/${encodeURIComponent(file.filename)}`;

        const insertResult = insertFile.run(
          originalName,
          file.filename,
          url,
          file.size
        );

        if (insertResult.changes === 0) {
          fs.unlinkSync(file.path);
          return findFile.get(originalName);
        }

        return {
          originalName,
          storedName: file.filename,
          size: file.size,
          url
        };
      })
    );

    const result = insertFiles(files);

    res.json({
      success: true,
      count: result.length,
      files: result
    });
  }
);

app.get("/api/files", basicAuth, (req, res) => {
  const files = db.prepare(`
    SELECT
      original_name AS name,
      stored_name,
      url,
      size,
      created_at
    FROM files
    ORDER BY id DESC
  `).all();

  res.json({ files });
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
