'use strict';
/* Журнал работ — сервер без внешних зависимостей (только стандартный Node.js). */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || process.env.CONTAINER_PORT || 80);
const PUBLIC_DIR = path.join(__dirname, 'public');
const PASSWORD = process.env.APP_PASSWORD || '677007';
const DAY = 86400000;

/* ---------- где хранить данные ---------- */
function pickDataDir(){
  const wanted = process.env.DATA_DIR || '/data';
  try{ fs.mkdirSync(wanted, { recursive:true }); fs.accessSync(wanted, fs.constants.W_OK); return wanted; }
  catch(e){
    const local = path.join(__dirname, 'data');
    fs.mkdirSync(local, { recursive:true });
    console.log('Постоянное хранилище недоступно, работаю в', local);
    return local;
  }
}
const DATA_DIR = pickDataDir();
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'db.json');
fs.mkdirSync(UPLOAD_DIR, { recursive:true });

/* ключ для подписи входа — переживает перезапуск */
const SECRET_FILE = path.join(DATA_DIR, 'secret.key');
let SECRET;
try{ SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim(); }
catch(e){ SECRET = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(SECRET_FILE, SECRET); }

/* ---------- пользователи ---------- */
const USERS = [
  { id:'katya',  name:'Катя',  color:'#A8385F' },
  { id:'zhenya', name:'Женя',  color:'#2E5EAA' },
  { id:'arian',  name:'Ариан', color:'#3C7A52' }
];
const userById = id => USERS.find(u => u.id === id);

/* ---------- данные ---------- */
const uid = () => crypto.randomBytes(5).toString('hex');

function seed(){
  const mk = rows => rows.map(r => ({
    id:uid(), task:r[0], who:r[1]||'', note:r[2]||'', due:'', files:[],
    done:false, by:null, at:new Date().toISOString()
  }));
  return {
    rev: 1,
    objects: [
      { id:uid(), name:'Гараж', tasks: mk([
        ['Отопление','Мишкин','Когда начнут? 18.08.26 — радиаторы первый этаж, счёт'],
        ['Ворота Импорт','Ворота Импорт','18.08.2026 пришли. С Александром переговорить'],
        ['Ворота Дорхан','Дорхан','+7 924 862-88-19. С Александром переговорить'],
        ['Асфальт въезд','','Ещё не договорились'],
        ['Водоснабжение','',''],
        ['Вентиляция','Вентпромстрой','Оплачено'],
        ['Откосы','',''],
        ['Водосток','Алексей',''],
        ['Документы ввод','Алексей',''],
        ['Туалет, душ','',''],
        ['Установка дверей','',''],
        ['Покраска спортзала','','Мешает отсутствие вентиляции'],
        ['Генератор для гаража','','5 кВт?']
      ])},
      { id:uid(), name:'Объект', tasks: mk([
        ['Окна для кассы','',''],
        ['Клей для пола','',''],
        ['Выравнивание пола','','Под вопросом'],
        ['Ёмкость для воды','',''],
        ['Покраска потолка','',''],
        ['Перила, перила второй этаж','Стеклорум','18.08 написал'],
        ['Генератор для склада','','Сколько кВт?']
      ])},
      { id:uid(), name:'Сладкая планета', tasks: [] }
    ],
    log: []
  };
}

let db;
try{
  db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  if(!Array.isArray(db.objects)) throw new Error('битый файл');
}catch(e){
  db = seed();
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
db.log = db.log || [];
db.rev = db.rev || 1;

let saveTimer = null;
function persist(){
  db.rev++;
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    const tmp = DB_FILE + '.tmp';
    fs.writeFile(tmp, JSON.stringify(db, null, 2), err => {
      if(err) return console.error('Не записал базу:', err.message);
      fs.rename(tmp, DB_FILE, e2 => e2 && console.error('Не переименовал базу:', e2.message));
    });
  }, 120);
}

function note(user, text){
  db.log.unshift({ id:uid(), at:new Date().toISOString(), by:user.id, text });
  if(db.log.length > 400) db.log.length = 400;
}
function stamp(task, user){ task.by = user.id; task.at = new Date().toISOString(); }

const findTask = id => {
  for(const o of db.objects){
    const t = o.tasks.find(x => x.id === id);
    if(t) return { obj:o, task:t };
  }
  return null;
};

/* ---------- вход ---------- */
function sign(payload){
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + mac;
}
function verify(token){
  if(!token || token.indexOf('.') < 0) return null;
  const [body, mac] = token.split('.');
  const good = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if(mac.length !== good.length) return null;
  if(!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(good))) return null;
  try{
    const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if(!p.exp || p.exp < Date.now()) return null;
    return userById(p.u) || null;
  }catch(e){ return null; }
}
function cookies(req){
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if(i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
const who = req => verify(cookies(req).zhurnal);

/* ---------- мелочи ---------- */
function send(res, code, obj, extra){
  res.writeHead(code, Object.assign({ 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store' }, extra || {}));
  res.end(JSON.stringify(obj));
}
function body(req, limit = 22 * 1024 * 1024){
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if(size > limit){ reject(new Error('слишком большой файл')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if(!chunks.length) return resolve({});
      try{ resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch(e){ reject(new Error('битый запрос')); }
    });
    req.on('error', reject);
  });
}
const clean = (s, max = 400) => String(s == null ? '' : s).replace(/\s+/g, ' ').trim().slice(0, max);
const quote = s => '«' + (s || 'без названия') + '»';

const MIME = { '.html':'text/html; charset=utf-8', '.js':'text/javascript; charset=utf-8',
  '.css':'text/css; charset=utf-8', '.svg':'image/svg+xml', '.png':'image/png', '.ico':'image/x-icon' };

function state(user){
  return { me:user, users:USERS, rev:db.rev, objects:db.objects, log:db.log.slice(0, 200) };
}

/* ---------- маршруты ---------- */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  try{
    /* --- вход и выход --- */
    if(p === '/api/login' && req.method === 'POST'){
      const b = await body(req, 4096);
      const u = userById(String(b.user || ''));
      const given = Buffer.from(String(b.password || ''));
      const real = Buffer.from(PASSWORD);
      const ok = u && given.length === real.length && crypto.timingSafeEqual(given, real);
      if(!ok){ await new Promise(r => setTimeout(r, 400)); return send(res, 401, { error:'Не тот пользователь или пароль' }); }
      const token = sign({ u:u.id, exp: Date.now() + 30 * DAY });
      return send(res, 200, { me:u }, {
        'Set-Cookie': 'zhurnal=' + token + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + (30 * 86400)
      });
    }
    if(p === '/api/logout' && req.method === 'POST'){
      return send(res, 200, { ok:true }, { 'Set-Cookie':'zhurnal=; Path=/; HttpOnly; Max-Age=0' });
    }

    /* --- всё ниже только для вошедших --- */
    const user = who(req);
    if(p.startsWith('/api/') || p.startsWith('/files/')){
      if(!user) return send(res, 401, { error:'Нужно войти' });
    }

    if(p === '/api/state' && req.method === 'GET') return send(res, 200, state(user));

    if(p === '/api/task' && req.method === 'POST'){
      const b = await body(req, 8192);
      const obj = db.objects.find(o => o.id === b.objectId);
      if(!obj) return send(res, 404, { error:'Объект не найден' });
      const title = clean(b.task, 200);
      if(!title) return send(res, 400, { error:'Пустая задача' });
      const t = { id:uid(), task:title, who:clean(b.who, 120), note:'', due:clean(b.due, 10),
                  files:[], done:false, by:user.id, at:new Date().toISOString() };
      obj.tasks.push(t);
      note(user, 'добавил задачу ' + quote(title) + ' — ' + obj.name);
      persist(); return send(res, 200, state(user));
    }

    if(/^\/api\/task\/[^/]+$/.test(p) && req.method === 'PATCH'){
      const hit = findTask(p.split('/')[3]);
      if(!hit) return send(res, 404, { error:'Задача не найдена' });
      const b = await body(req, 8192);
      const t = hit.task, changes = [];
      if('task' in b && clean(b.task, 200) !== t.task){ const v = clean(b.task, 200); if(v){ changes.push('название → ' + quote(v)); t.task = v; } }
      if('who' in b && clean(b.who, 120) !== t.who){ t.who = clean(b.who, 120); changes.push(t.who ? 'исполнитель → ' + t.who : 'убрал исполнителя'); }
      if('note' in b && clean(b.note, 2000) !== t.note){ t.note = clean(b.note, 2000); changes.push('заметка'); }
      if('due' in b && clean(b.due, 10) !== t.due){ t.due = clean(b.due, 10); changes.push(t.due ? 'срок → ' + t.due.split('-').reverse().join('.') : 'снял срок'); }
      if('done' in b && !!b.done !== !!t.done){ t.done = !!b.done; changes.push(t.done ? 'ОТМЕТИЛ СДЕЛАННЫМ' : 'вернул в работу'); }
      if(changes.length){
        stamp(t, user);
        note(user, quote(t.task) + ': ' + changes.join(', '));
        persist();
      }
      return send(res, 200, state(user));
    }

    if(/^\/api\/task\/[^/]+$/.test(p) && req.method === 'DELETE'){
      const hit = findTask(p.split('/')[3]);
      if(!hit) return send(res, 404, { error:'Задача не найдена' });
      hit.obj.tasks = hit.obj.tasks.filter(x => x.id !== hit.task.id);
      note(user, 'удалил задачу ' + quote(hit.task.task) + ' — ' + hit.obj.name);
      persist(); return send(res, 200, state(user));
    }

    /* файл приходит как base64 внутри JSON — так не нужен разбор multipart */
    if(/^\/api\/task\/[^/]+\/file$/.test(p) && req.method === 'POST'){
      const hit = findTask(p.split('/')[3]);
      if(!hit) return send(res, 404, { error:'Задача не найдена' });
      const b = await body(req);
      const raw = String(b.data || '');
      const buf = Buffer.from(raw.slice(raw.indexOf(',') + 1), 'base64');
      if(!buf.length) return send(res, 400, { error:'Пустой файл' });
      if(buf.length > 15 * 1024 * 1024) return send(res, 413, { error:'Файл больше 15 МБ' });
      const name = clean(b.name, 160) || 'файл';
      const ext = (path.extname(name) || '').slice(0, 10).replace(/[^\w.]/g, '');
      const stored = uid() + ext;
      fs.writeFileSync(path.join(UPLOAD_DIR, stored), buf);
      const rec = { id:uid(), name, stored, size:buf.length, type:clean(b.type, 80),
                    by:user.id, at:new Date().toISOString() };
      hit.task.files.push(rec);
      stamp(hit.task, user);
      note(user, 'приложил файл «' + name + '» к ' + quote(hit.task.task));
      persist(); return send(res, 200, state(user));
    }

    if(/^\/api\/task\/[^/]+\/file\/[^/]+$/.test(p) && req.method === 'DELETE'){
      const parts = p.split('/');
      const hit = findTask(parts[3]);
      if(!hit) return send(res, 404, { error:'Задача не найдена' });
      const f = hit.task.files.find(x => x.id === parts[5]);
      if(!f) return send(res, 404, { error:'Файл не найден' });
      hit.task.files = hit.task.files.filter(x => x.id !== f.id);
      fs.unlink(path.join(UPLOAD_DIR, f.stored), () => {});
      stamp(hit.task, user);
      note(user, 'убрал файл «' + f.name + '» из ' + quote(hit.task.task));
      persist(); return send(res, 200, state(user));
    }

    if(p === '/api/object' && req.method === 'POST'){
      const b = await body(req, 4096);
      const name = clean(b.name, 80);
      if(!name) return send(res, 400, { error:'Пустое название' });
      db.objects.push({ id:uid(), name, tasks:[] });
      note(user, 'добавил объект ' + quote(name));
      persist(); return send(res, 200, state(user));
    }
    if(/^\/api\/object\/[^/]+$/.test(p) && req.method === "PATCH"){
      const o = db.objects.find(x => x.id === p.split('/')[3]);
      if(!o) return send(res, 404, { error:'Объект не найден' });
      const b = await body(req, 4096);
      const name = clean(b.name, 80);
      if(name && name !== o.name){ note(user, 'переименовал ' + quote(o.name) + ' → ' + quote(name)); o.name = name; persist(); }
      return send(res, 200, state(user));
    }
    if(p.startsWith('/api/object/') && req.method === 'DELETE'){
      const id = p.split('/')[3];
      if(db.objects.length < 2) return send(res, 400, { error:'Последний объект удалить нельзя' });
      const o = db.objects.find(x => x.id === id);
      if(!o) return send(res, 404, { error:'Объект не найден' });
      db.objects = db.objects.filter(x => x.id !== id);
      note(user, 'удалил объект ' + quote(o.name) + ' (задач: ' + o.tasks.length + ')');
      persist(); return send(res, 200, state(user));
    }

    /* --- отдача приложенных файлов --- */
    if(p.startsWith('/files/')){
      const stored = path.basename(decodeURIComponent(p.slice(7)));
      let rec = null;
      for(const o of db.objects) for(const t of o.tasks){
        const f = t.files.find(x => x.stored === stored);
        if(f){ rec = f; break; }
      }
      const full = path.join(UPLOAD_DIR, stored);
      if(!rec || !fs.existsSync(full)) { res.writeHead(404); return res.end('Файл не найден'); }
      res.writeHead(200, {
        'Content-Type': rec.type || 'application/octet-stream',
        'Content-Length': fs.statSync(full).size,
        'Content-Disposition': 'inline; filename*=UTF-8\'\'' + encodeURIComponent(rec.name),
        'Cache-Control': 'private, max-age=600'
      });
      return fs.createReadStream(full).pipe(res);
    }

    /* --- статика --- */
    let file = p === '/' ? '/index.html' : p;
    const full = path.join(PUBLIC_DIR, path.normalize(file).replace(/^(\.\.[/\\])+/, ''));
    if(fs.existsSync(full) && fs.statSync(full).isFile()){
      res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream',
                           'Cache-Control':'no-cache' });
      return fs.createReadStream(full).pipe(res);
    }
    res.writeHead(404, { 'Content-Type':'text/plain; charset=utf-8' });
    res.end('Страница не найдена');

  }catch(err){
    console.error(err);
    if(!res.headersSent) send(res, 400, { error: err.message || 'Ошибка запроса' });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('Журнал работ слушает порт ' + PORT + ', данные в ' + DATA_DIR);
});
