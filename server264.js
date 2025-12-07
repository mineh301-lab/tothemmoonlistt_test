// tothemoonlist.com - server.js
// (c) 2025
// server264 - WebSocket 지수 백오프 + HTTP Rate Limit 완화 (see Version_History.txt)

const express = require('express');
const WebSocket = require('ws');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---
//  보안 환경변수 로드 및 검증
// - 필수 환경변수가 없으면 랜덤 생성 후 로그 출력
// - 기본값 하드코딩 금지!
// ---
function loadSecurityEnv(envName, defaultLength = 32) {
  const value = process.env[envName];
  if (value) {
    console.log('[SECURITY] ' + envName + ' 환경변수 로드됨');
    return value;
  }
  // 환경변수 미설정 시 랜덤 값 생성
  const randomValue = crypto.randomBytes(defaultLength).toString('hex').slice(0, defaultLength);
  console.warn('[SECURITY] [WARN] ' + envName + ' 환경변수 미설정!');
  console.warn('   └─ 임시 생성된 값: ' + randomValue);
  console.warn('   └─ Railway Variables에 설정하세요!');
  return randomValue;
}

// 보안 환경변수 로드 (기본값 하드코딩 금지!)
const ADMIN_CHAT_CMD = loadSecurityEnv('ADMIN_CHAT_CMD', 16);   // 관리자 채팅 명령어
const ADMIN_API_KEY = loadSecurityEnv('ADMIN_API_KEY', 32);     // 피드백 조회 키
const SECURITY_FEEDBACK_SALT = loadSecurityEnv('FEEDBACK_SALT', 32);  // IP 해싱용 (피드백)
const CHAT_SALT = loadSecurityEnv('CHAT_SALT', 32);             // IP 해싱용 (채팅)

console.log('[SECURITY] 보안 환경변수 로드 완료');

// ---
//  실제 클라이언트 IP 추출 헬퍼
// - Reverse Proxy 환경(Railway, AWS, Cloudflare) 대응
// - x-forwarded-for 헤더 우선 확인 (첫 번째 IP = 실제 클라이언트)
// - 헤더 없으면 socket.remoteAddress 사용
// ---
function getClientIp(req) {
  if (!req) return 'unknown';
  
  // x-forwarded-for: "client, proxy1, proxy2" 형태
  // 첫 번째 IP가 실제 클라이언트 IP
  const xForwardedFor = req.headers && req.headers['x-forwarded-for'];
  if (xForwardedFor) {
    const firstIp = xForwardedFor.split(',')[0].trim();
    if (firstIp) return firstIp;
  }
  
  // x-real-ip 헤더 (nginx 등에서 사용)
  const xRealIp = req.headers && req.headers['x-real-ip'];
  if (xRealIp) return xRealIp.trim();
  
  // 직접 연결인 경우 socket.remoteAddress
  if (req.socket && req.socket.remoteAddress) {
    return req.socket.remoteAddress;
  }
  
  // req.connection (Express에서 사용)
  if (req.connection && req.connection.remoteAddress) {
    return req.connection.remoteAddress;
  }
  
  return 'unknown';
}

const app = express();
const PORT = process.env.PORT || 8001;

let coinData = [];

// ---
// 중앙 통제식 업비트 API 스케줄러 (429 에러 근본 해결)
// ---
const UpbitApiScheduler = {
  queue: [],           // 대기열
  isProcessing: false, // 현재 처리 중인지
  isPaused: false,     // 429 에러로 인한 일시 정지 상태
  lastRequestTime: 0,  // 마지막 요청 시간
  MIN_INTERVAL: 150,   //  최소 요청 간격 (150ms = 초당 ~6.7회, 429 에러 방지용 안전값)
  PAUSE_DURATION: 3000, // 429 발생 시 일시 정지 시간 (3초)
  
  // 요청 추가
  enqueue(requestFn) {
    return new Promise((resolve, reject) => {
      this.queue.push({ requestFn, resolve, reject });
      this.processQueue();
    });
  },
  
  // 대기열 처리
  async processQueue() {
    if (this.isProcessing || this.isPaused || this.queue.length === 0) {
      return;
    }
    
    this.isProcessing = true;
    
    while (this.queue.length > 0 && !this.isPaused) {
      const { requestFn, resolve, reject } = this.queue.shift();
      
      // 최소 간격 보장
      const now = Date.now();
      const elapsed = now - this.lastRequestTime;
      if (elapsed < this.MIN_INTERVAL) {
        await new Promise(r => setTimeout(r, this.MIN_INTERVAL - elapsed));
      }
      
      try {
        this.lastRequestTime = Date.now();
        const result = await requestFn();
        resolve(result);
      } catch (error) {
        // 429 에러 감지 시 일시 정지
        if (error.response && error.response.status === 429) {
          console.warn('[WARN] [429] 업비트 Rate Limit 감지! ' + this.PAUSE_DURATION/1000 + '초 대기열 일시 정지...');
          this.isPaused = true;
          
          // 현재 요청은 실패 처리
          reject(error);
          
          // 일시 정지 후 재개
          setTimeout(() => {
            console.log('[RESUME] 업비트 API 대기열 재개');
            this.isPaused = false;
            this.processQueue();
          }, this.PAUSE_DURATION);
          
          break;
        } else {
          reject(error);
        }
      }
    }
    
    this.isProcessing = false;
  },
  
  // 간편 요청 메서드 (URL만 전달)
  async request(url, options = {}) {
    return this.enqueue(() => axios.get(url, { timeout: 10000, ...options }));
  },
  
  // 대기열 상태 확인
  getStatus() {
    return {
      queueLength: this.queue.length,
      isProcessing: this.isProcessing,
      isPaused: this.isPaused
    };
  },
  
  // 대기열 비우기 (긴급 시)
  clearQueue() {
    const cleared = this.queue.length;
    this.queue.forEach(({ reject }) => reject(new Error('Queue cleared')));
    this.queue = [];
    return cleared;
  }
};

// ---
// 동적 마켓 코드 (하드코딩 제거 - 명세 1)
// ---
let UPBIT_MARKETS = [];    // ['BTC', 'ETH', 'XRP', ...] 형태로 저장됨
let BITHUMB_MARKETS = [];  // ['BTC', 'ETH', 'XRP', ...] 형태로 저장됨
let marketsLoaded = false; // 마켓 로딩 완료 플래그

// ---
//  글로벌 거래소 마켓 배열
//  심볼 정규화: 기초 자산명(Base Asset)만 저장
// ---
let BINANCE_SPOT_MARKETS = [];     // ['BTC', 'ETH', ...] 정규화된 심볼
let BINANCE_FUTURES_MARKETS = [];  // ['BTC', 'ETH', ...] 정규화된 심볼 (USDT-M 무기한)
let OKX_SPOT_MARKETS = [];         // ['BTC', 'ETH', ...] 정규화된 심볼
let OKX_FUTURES_MARKETS = [];      // ['BTC', 'ETH', ...] 정규화된 심볼 (USDT 무기한 스왑)

// ---
//  ExchangeRateManager - 원/달러 환율 관리 (유효성 검사 추가)
// - 업비트 + 빗썸 교차 검증 (단일 거래소 의존 제거)
// - 3% 이상 괴리 시 이상치 배제 (lastKnownRate 기준)
// - 1분 간격 폴링 (실시간 틱 의존도 낮춤)
// -  파일 캐시로 즉시 로딩 (서버 재시작 딜레이 제거)
// -  24시간 유효성 검사 (만료된 데이터 폐기)
// ---

// ---
//  Railway Volume 지원 - 데이터 저장 경로 설정
// - 환경변수 DATA_DIR로 설정 가능 (기본값: 현재 디렉토리)
// - Railway Volume 사용 시: DATA_DIR=/data 설정
// - 서버 재시작/재배포 시에도 데이터 영구 보존
// ---
const DATA_DIR = process.env.DATA_DIR || __dirname;

//  데이터 디렉토리 존재 확인 및 생성
if (DATA_DIR !== __dirname && !fs.existsSync(DATA_DIR)) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    console.log('[DIR]  데이터 디렉토리 생성: ' + DATA_DIR);
  } catch (err) {
    console.error('[ERROR]  데이터 디렉토리 생성 실패:', err.message);
    console.log('   └─ 기본 디렉토리 사용: ' + __dirname);
  }
}

//  시작 시 DATA_DIR 상세 로그
console.log('');
console.log('═══════════════════════════════════════════════════════════════');
console.log('[INIT]  데이터 디렉토리 확인');
console.log('═══════════════════════════════════════════════════════════════');
console.log('   DATA_DIR: ' + DATA_DIR);
console.log('   __dirname: ' + __dirname);
console.log('   Railway Volume 모드: ' + (DATA_DIR !== __dirname ? 'YES' : 'NO'));

//  디렉토리 내 파일 목록 확인
try {
  if (fs.existsSync(DATA_DIR)) {
    const files = fs.readdirSync(DATA_DIR);
    const jsonFiles = files.filter(f => f.endsWith('.json'));
    console.log('   JSON 파일 수: ' + jsonFiles.length + '개');
    
    // Multi-TF 캔들 파일 확인
    const multiTfFiles = jsonFiles.filter(f => f.startsWith('multi_tf_'));
    console.log('   Multi-TF 캔들 파일: ' + multiTfFiles.length + '개');
    multiTfFiles.forEach(f => {
      const filePath = path.join(DATA_DIR, f);
      const stats = fs.statSync(filePath);
      const sizeMB = (stats.size / 1024 / 1024).toFixed(2);
      const age = Math.round((Date.now() - stats.mtime.getTime()) / 1000 / 60);
      console.log('      ' + f + ': ' + sizeMB + 'MB, ' + age + '분 전 수정');
    });
    
    if (multiTfFiles.length === 0) {
      console.log('   [WARN] Multi-TF 캔들 파일 없음! 전체 백필 필요');
    }
  } else {
    console.log('   [WARN] DATA_DIR 존재하지 않음!');
  }
} catch (dirErr) {
  console.error('   [ERROR] 디렉토리 읽기 실패:', dirErr.message);
}
console.log('═══════════════════════════════════════════════════════════════');
console.log('');

// ---
//  동시접속자 통계 관리자
// - 피크 기록 파일 저장/복원 (서버 재시작 후에도 유지)
// - 시간대별 평균 접속자 (오전/오후/저녁/심야)
// - 일별/주별 통계 JSON 저장
// - 50명+ 알림 로그
// ---
const USER_STATS_FILE = path.join(DATA_DIR, 'user_stats.json');
const USER_ALERT_THRESHOLD = 50;  // 이 수 이상이면 알림 로그

const UserStatsManager = {
  // 통계 데이터 구조
  stats: {
    // 전체 피크 기록
    allTimePeak: { count: 0, timestamp: null },
    
    // 오늘 피크 기록
    todayPeak: { count: 0, timestamp: null, date: null },
    
    // 시간대별 통계 (오전/오후/저녁/심야)
    // { morning: { sum: 0, samples: 0 }, afternoon: {...}, evening: {...}, night: {...} }
    timePeriods: {
      morning: { sum: 0, samples: 0 },    // 06:00~12:00
      afternoon: { sum: 0, samples: 0 },  // 12:00~18:00
      evening: { sum: 0, samples: 0 },    // 18:00~24:00
      night: { sum: 0, samples: 0 }       // 00:00~06:00
    },
    
    // 일별 통계 (최근 30일)
    // { "2025-12-04": { samples: [15, 20, 18, ...], peak: 42, total: 0 } }
    daily: {},
    
    // 주별 통계 (최근 12주)
    // { "2025-W49": { avgUsers: 25.5, peak: 100, sampleCount: 336 } }
    weekly: {},
    
    // 마지막 저장 시간
    lastSaved: null
  },
  
  // 시간대 판별 (한국 시간 기준)
  getTimePeriod(hour) {
    if (hour >= 6 && hour < 12) return 'morning';      // 오전
    if (hour >= 12 && hour < 18) return 'afternoon';   // 오후
    if (hour >= 18 && hour < 24) return 'evening';     // 저녁
    return 'night';                                     // 심야 (0~6시)
  },
  
  // 시간대 한글명
  getTimePeriodName(period) {
    const names = {
      morning: '오전(06-12)',
      afternoon: '오후(12-18)',
      evening: '저녁(18-24)',
      night: '심야(00-06)'
    };
    return names[period] || period;
  },
  
  // ISO 주차 계산
  getWeekNumber(date) {
    const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
    const dayNum = d.getUTCDay() || 7;
    d.setUTCDate(d.getUTCDate() + 4 - dayNum);
    const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
    const weekNo = Math.ceil((((d - yearStart) / 86400000) + 1) / 7);
    return d.getUTCFullYear() + '-W' + String(weekNo).padStart(2, '0');
  },
  
  // 파일에서 통계 로드
  loadFromFile() {
    try {
      if (fs.existsSync(USER_STATS_FILE)) {
        const data = JSON.parse(fs.readFileSync(USER_STATS_FILE, 'utf8'));
        
        // 기존 데이터 병합 (없는 필드는 기본값 유지)
        if (data.allTimePeak) this.stats.allTimePeak = data.allTimePeak;
        if (data.todayPeak) this.stats.todayPeak = data.todayPeak;
        if (data.timePeriods) this.stats.timePeriods = data.timePeriods;
        if (data.daily) this.stats.daily = data.daily;
        if (data.weekly) this.stats.weekly = data.weekly;
        
        console.log('[USERS]  통계 파일 로드 성공!');
        console.log('   └─ 역대 피크: ' + this.stats.allTimePeak.count + '명 (' + (this.stats.allTimePeak.timestamp || 'N/A') + ')');
        
        // 오래된 일별/주별 데이터 정리
        this.cleanupOldData();
        
        return true;
      }
    } catch (err) {
      console.error('[USERS]  통계 파일 로드 실패:', err.message);
    }
    return false;
  },
  
  // 파일에 통계 저장
  saveToFile() {
    try {
      this.stats.lastSaved = new Date().toISOString();
      fs.writeFileSync(USER_STATS_FILE, JSON.stringify(this.stats, null, 2), 'utf8');
      return true;
    } catch (err) {
      console.error('[USERS]  통계 파일 저장 실패:', err.message);
      return false;
    }
  },
  
  // 오래된 데이터 정리 (일별 30일, 주별 12주)
  cleanupOldData() {
    const now = new Date();
    
    // 일별: 30일 이상 된 데이터 삭제
    const thirtyDaysAgo = new Date(now);
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const cutoffDate = thirtyDaysAgo.toISOString().split('T')[0];
    
    for (const dateKey of Object.keys(this.stats.daily)) {
      if (dateKey < cutoffDate) {
        delete this.stats.daily[dateKey];
      }
    }
    
    // 주별: 12주 이상 된 데이터 삭제
    const twelveWeeksAgo = new Date(now);
    twelveWeeksAgo.setDate(twelveWeeksAgo.getDate() - 84);
    const cutoffWeek = this.getWeekNumber(twelveWeeksAgo);
    
    for (const weekKey of Object.keys(this.stats.weekly)) {
      if (weekKey < cutoffWeek) {
        delete this.stats.weekly[weekKey];
      }
    }
  },
  
  // 샘플 기록 (3분마다 호출)
  recordSample(currentUsers, tfStats) {
    const now = new Date();
    const kstNow = new Date(now.toLocaleString('en-US', { timeZone: 'Asia/Seoul' }));
    const hour = kstNow.getHours();
    const dateStr = kstNow.toISOString().split('T')[0];
    const weekStr = this.getWeekNumber(kstNow);
    const timestamp = now.toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' });
    const period = this.getTimePeriod(hour);
    
    let alerts = [];
    
    // 1. 전체 피크 체크
    if (currentUsers > this.stats.allTimePeak.count) {
      const oldPeak = this.stats.allTimePeak.count;
      this.stats.allTimePeak = { count: currentUsers, timestamp: timestamp };
      alerts.push('[PEAK] 역대 최고 접속자 갱신! ' + oldPeak + ' -> ' + currentUsers + '명');
    }
    
    // 2. 오늘 피크 체크 (날짜 바뀌면 리셋)
    if (this.stats.todayPeak.date !== dateStr) {
      this.stats.todayPeak = { count: 0, timestamp: null, date: dateStr };
    }
    if (currentUsers > this.stats.todayPeak.count) {
      this.stats.todayPeak = { count: currentUsers, timestamp: timestamp, date: dateStr };
    }
    
    // 3. 시간대별 통계 업데이트
    this.stats.timePeriods[period].sum += currentUsers;
    this.stats.timePeriods[period].samples += 1;
    
    // 4. 일별 통계 업데이트
    if (!this.stats.daily[dateStr]) {
      this.stats.daily[dateStr] = { samples: [], peak: 0, total: 0 };
    }
    this.stats.daily[dateStr].samples.push(currentUsers);
    this.stats.daily[dateStr].total += currentUsers;
    if (currentUsers > this.stats.daily[dateStr].peak) {
      this.stats.daily[dateStr].peak = currentUsers;
    }
    
    // 5. 주별 통계 업데이트
    if (!this.stats.weekly[weekStr]) {
      this.stats.weekly[weekStr] = { total: 0, peak: 0, sampleCount: 0 };
    }
    this.stats.weekly[weekStr].total += currentUsers;
    this.stats.weekly[weekStr].sampleCount += 1;
    if (currentUsers > this.stats.weekly[weekStr].peak) {
      this.stats.weekly[weekStr].peak = currentUsers;
    }
    
    // 6. 50명+ 알림 체크
    if (currentUsers >= USER_ALERT_THRESHOLD) {
      alerts.push('[ALERT] 동시접속 ' + currentUsers + '명 돌파!');
    }
    
    return {
      timestamp,
      currentUsers,
      period,
      periodName: this.getTimePeriodName(period),
      todayPeak: this.stats.todayPeak.count,
      allTimePeak: this.stats.allTimePeak.count,
      tfStats,
      alerts
    };
  },
  
  // 시간대별 평균 조회
  getTimePeriodAverages() {
    const result = {};
    for (const [period, data] of Object.entries(this.stats.timePeriods)) {
      result[period] = data.samples > 0 
        ? Math.round(data.sum / data.samples * 10) / 10 
        : 0;
    }
    return result;
  },
  
  // 일별 요약 로그 (자정에 호출)
  getDailySummary(dateStr) {
    const data = this.stats.daily[dateStr];
    if (!data || data.samples.length === 0) return null;
    
    const avg = Math.round(data.total / data.samples.length * 10) / 10;
    return {
      date: dateStr,
      average: avg,
      peak: data.peak,
      sampleCount: data.samples.length
    };
  },
  
  // 주별 요약 조회
  getWeeklySummary(weekStr) {
    const data = this.stats.weekly[weekStr];
    if (!data || data.sampleCount === 0) return null;
    
    return {
      week: weekStr,
      average: Math.round(data.total / data.sampleCount * 10) / 10,
      peak: data.peak,
      sampleCount: data.sampleCount
    };
  }
};

// ---
//  피드백 시스템 - 파일 경로 및 설정
//  FEEDBACK_SALT는 상단에서 환경변수로 로드됨
// ---
const FEEDBACK_FILE = path.join(DATA_DIR, 'feedback.jsonl');

// express.json() 미들웨어 (피드백 API용)
app.use(express.json({ limit: '10kb' }));

// ---
//  npm audit 취약점 체크 (server260)
// - 서버 시작 시 npm audit 실행
// - high/critical 취약점 발견 시 경고 로그
// - 서버 동작에는 영향 없음 (정보 제공 목적)
// ---
const { execSync } = require('child_process');

function checkNpmAudit() {
  console.log('');
  console.log('[SECURITY] npm audit 취약점 검사 시작...');
  
  try {
    // npm audit --json 실행 (audit-level=high: high/critical만 exit code 1)
    const result = execSync('npm audit --json 2>/dev/null', {
      encoding: 'utf8',
      timeout: 30000,  // 30초 타임아웃
      maxBuffer: 1024 * 1024  // 1MB
    });
    
    const audit = JSON.parse(result);
    const vulns = audit.metadata?.vulnerabilities || {};
    const total = (vulns.high || 0) + (vulns.critical || 0);
    
    if (total === 0) {
      console.log('[OK] npm audit: high/critical 취약점 없음');
      if (vulns.moderate || vulns.low) {
        console.log('   [INFO] moderate: ' + (vulns.moderate || 0) + ', low: ' + (vulns.low || 0) + ' (권장: npm audit fix)');
      }
    } else {
      console.warn('[WARN] npm audit: 취약점 발견!');
      console.warn('   [CRITICAL] ' + (vulns.critical || 0) + '개');
      console.warn('   [HIGH] ' + (vulns.high || 0) + '개');
      console.warn('   [ACTION] npm audit fix --force 또는 패키지 업데이트 권장');
    }
    
    return { success: true, vulnerabilities: vulns };
    
  } catch (error) {
    // npm audit 실행 실패 또는 취약점 발견 시 exit code 1
    if (error.stdout) {
      try {
        const audit = JSON.parse(error.stdout);
        const vulns = audit.metadata?.vulnerabilities || {};
        const total = (vulns.high || 0) + (vulns.critical || 0);
        
        if (total > 0) {
          console.warn('[WARN] npm audit: 취약점 발견!');
          console.warn('   [CRITICAL] ' + (vulns.critical || 0) + '개');
          console.warn('   [HIGH] ' + (vulns.high || 0) + '개');
          console.warn('   [MODERATE] ' + (vulns.moderate || 0) + '개');
          console.warn('   [LOW] ' + (vulns.low || 0) + '개');
          console.warn('   [ACTION] npm audit fix 실행 권장');
          return { success: true, vulnerabilities: vulns };
        }
      } catch (parseError) {
        // JSON 파싱 실패
      }
    }
    
    // npm audit 자체 실패 (node_modules 없음 등)
    console.log('[INFO] npm audit 실행 불가 (node_modules 없거나 네트워크 오류)');
    return { success: false, error: error.message };
  }
}

// ---
//  WebSocket 재연결 지수 백오프 + 지터 (server264)
// - 고정 딜레이 → 지수 백오프로 변경 (thundering herd 방지)
// - 최소 1초, 최대 60초, +-20% 랜덤 지터
// ---
const WsReconnectManager = {
  // 거래소별 재연결 시도 횟수 추적
  attempts: {
    upbit: 0,
    bithumb: 0,
    binance_spot: 0,
    binance_futures: 0,
    okx_spot: 0,
    okx_futures: 0
  },

  // 설정값
  BASE_DELAY: 1000,      // 기본 딜레이 1초
  MAX_DELAY: 60000,      // 최대 딜레이 60초
  JITTER_FACTOR: 0.2,    // +-20% 지터

  // 다음 재연결 딜레이 계산
  getNextDelay(exchange) {
    const attempt = this.attempts[exchange] || 0;

    // 지수 백오프: 1초 → 2초 → 4초 → 8초 → ... → 최대 60초
    let delay = Math.min(
      this.BASE_DELAY * Math.pow(2, attempt),
      this.MAX_DELAY
    );

    // 랜덤 지터 추가 (+-20%)
    const jitter = delay * this.JITTER_FACTOR * (Math.random() * 2 - 1);
    delay = Math.round(delay + jitter);

    // 시도 횟수 증가
    this.attempts[exchange] = attempt + 1;

    return delay;
  },

  // 연결 성공 시 시도 횟수 리셋
  resetAttempts(exchange) {
    this.attempts[exchange] = 0;
  },

  // 현재 상태 조회 (디버깅용)
  getStatus() {
    return { ...this.attempts };
  }
};

// ---
//  WebSocket 보안 모니터링 (server260)
// - 비정상 연결 패턴 감지 및 로깅
// - DDoS/DoS 공격 조기 감지
// - 3분마다 통계 요약 로그
// ---
const WS_MONITOR_FILE = path.join(DATA_DIR, 'ws_security_log.json');
const WS_MONITOR_INTERVAL = 180000;  // 3분마다 통계 출력
const WS_MAX_IP_ENTRIES = 1000;      // ipActivity 최대 엔트리 수 (server264)

const WsSecurityMonitor = {
  // 통계 데이터
  stats: {
    // 연결 통계
    totalConnections: 0,       // 총 연결 수 (누적)
    totalDisconnections: 0,    // 총 연결 해제 수 (누적)
    currentConnections: 0,     // 현재 연결 수
    peakConnections: 0,        // 피크 연결 수
    peakTime: null,            // 피크 시간
    
    // 보안 이벤트 카운터
    rateLimitViolations: 0,    // Rate Limit 위반 총 횟수
    connectionRejections: 0,   // 연결 거부 총 횟수
    rapidReconnects: 0,        // 빠른 재연결 감지 횟수
    suspiciousPatterns: 0,     // 의심스러운 패턴 감지 횟수
    
    // IP별 통계 (최근 10분)
    ipActivity: new Map(),     // IP -> { connects: [], disconnects: [], violations: 0 }
    
    // 시간별 통계
    hourlyStats: {},           // { "2025-12-07T15": { connects: 0, disconnects: 0, violations: 0 } }
    
    // 마지막 리셋 시간
    lastReset: Date.now(),
    
    // 알림 발생 기록 (중복 알림 방지)
    lastAlerts: {}
  },
  
  // 연결 기록
  recordConnection(ip) {
    this.stats.totalConnections++;
    this.stats.currentConnections++;
    
    // 피크 체크
    if (this.stats.currentConnections > this.stats.peakConnections) {
      this.stats.peakConnections = this.stats.currentConnections;
      this.stats.peakTime = new Date().toISOString();
    }
    
    // IP별 활동 기록
    this.recordIpActivity(ip, 'connect');
    
    // 시간별 통계
    this.recordHourlyEvent('connects');
    
    // 빠른 재연결 감지 (10초 내 3회 이상)
    this.checkRapidReconnect(ip);
  },
  
  // 연결 해제 기록
  recordDisconnection(ip) {
    this.stats.totalDisconnections++;
    this.stats.currentConnections = Math.max(0, this.stats.currentConnections - 1);
    
    // IP별 활동 기록
    this.recordIpActivity(ip, 'disconnect');
    
    // 시간별 통계
    this.recordHourlyEvent('disconnects');
  },
  
  // Rate Limit 위반 기록
  recordRateLimitViolation(ip, clientId) {
    this.stats.rateLimitViolations++;
    
    // IP별 위반 기록
    const ipData = this.getIpData(ip);
    ipData.violations++;
    
    // 시간별 통계
    this.recordHourlyEvent('violations');
    
    // 반복 위반자 감지 (10분 내 5회 이상)
    if (ipData.violations >= 5) {
      this.logSecurityEvent('REPEAT_VIOLATOR', {
        ip: this.maskIp(ip),
        violations: ipData.violations,
        clientId: clientId
      });
    }
  },
  
  // 연결 거부 기록
  recordConnectionRejection(ip, reason) {
    this.stats.connectionRejections++;
    
    // IP별 거부 기록
    const ipData = this.getIpData(ip);
    ipData.rejections = (ipData.rejections || 0) + 1;
    
    // 시간별 통계
    this.recordHourlyEvent('rejections');
    
    // 반복 거부 감지 (10분 내 10회 이상)
    if (ipData.rejections >= 10) {
      this.logSecurityEvent('PERSISTENT_REJECT', {
        ip: this.maskIp(ip),
        rejections: ipData.rejections,
        reason: reason
      });
    }
  },
  
  // IP별 활동 기록
  recordIpActivity(ip, type) {
    // ipActivity 최대 엔트리 제한 (server264)
    if (this.stats.ipActivity.size >= WS_MAX_IP_ENTRIES) {
      // 가장 오래된 엔트리 제거 (firstSeen 기준)
      let oldestIp = null;
      let oldestTime = Infinity;
      for (const [existingIp, data] of this.stats.ipActivity) {
        if (data.firstSeen < oldestTime) {
          oldestTime = data.firstSeen;
          oldestIp = existingIp;
        }
      }
      if (oldestIp) {
        this.stats.ipActivity.delete(oldestIp);
      }
    }

    const ipData = this.getIpData(ip);
    const now = Date.now();

    if (type === 'connect') {
      ipData.connects.push(now);
    } else {
      ipData.disconnects.push(now);
    }

    // 10분 이상 된 기록 정리
    const tenMinAgo = now - 600000;
    ipData.connects = ipData.connects.filter(t => t > tenMinAgo);
    ipData.disconnects = ipData.disconnects.filter(t => t > tenMinAgo);
  },
  
  // IP 데이터 조회 (없으면 생성)
  getIpData(ip) {
    if (!this.stats.ipActivity.has(ip)) {
      this.stats.ipActivity.set(ip, {
        connects: [],
        disconnects: [],
        violations: 0,
        rejections: 0,
        firstSeen: Date.now()
      });
    }
    return this.stats.ipActivity.get(ip);
  },
  
  // 빠른 재연결 감지
  checkRapidReconnect(ip) {
    const ipData = this.getIpData(ip);
    const now = Date.now();
    const tenSecAgo = now - 10000;
    
    // 10초 내 연결 횟수
    const recentConnects = ipData.connects.filter(t => t > tenSecAgo).length;
    
    if (recentConnects >= 3) {
      this.stats.rapidReconnects++;
      this.logSecurityEvent('RAPID_RECONNECT', {
        ip: this.maskIp(ip),
        connectsIn10s: recentConnects
      });
    }
  },
  
  // 시간별 이벤트 기록
  recordHourlyEvent(type) {
    const hourKey = new Date().toISOString().slice(0, 13);  // "2025-12-07T15"
    
    if (!this.stats.hourlyStats[hourKey]) {
      this.stats.hourlyStats[hourKey] = {
        connects: 0,
        disconnects: 0,
        violations: 0,
        rejections: 0
      };
    }
    
    this.stats.hourlyStats[hourKey][type]++;
    
    // 24시간 이상 된 통계 정리
    const cutoff = new Date(Date.now() - 86400000).toISOString().slice(0, 13);
    for (const key of Object.keys(this.stats.hourlyStats)) {
      if (key < cutoff) {
        delete this.stats.hourlyStats[key];
      }
    }
  },
  
  // 보안 이벤트 로그 (중복 방지)
  logSecurityEvent(eventType, data) {
    const now = Date.now();
    const key = eventType + ':' + (data.ip || 'unknown');
    
    // 같은 이벤트는 5분에 1번만 로그
    if (this.stats.lastAlerts[key] && now - this.stats.lastAlerts[key] < 300000) {
      return;
    }
    
    this.stats.lastAlerts[key] = now;
    this.stats.suspiciousPatterns++;
    
    console.warn('[WS-SECURITY] ' + eventType + ':', JSON.stringify(data));
  },
  
  // IP 마스킹 (개인정보 보호)
  maskIp(ip) {
    if (!ip || ip === 'unknown') return 'unknown';
    // 마지막 8자리만 표시
    return '***' + ip.slice(-8);
  },
  
  // 통계 요약 로그 출력
  logSummary() {
    const uptime = Math.round((Date.now() - this.stats.lastReset) / 60000);
    
    console.log('');
    console.log('[WS-MONITOR] WebSocket 보안 통계 (' + uptime + '분 경과)');
    console.log('   [CONN] 현재: ' + this.stats.currentConnections + ', 피크: ' + this.stats.peakConnections + ', 총: ' + this.stats.totalConnections);
    console.log('   [SECURITY] Rate Limit 위반: ' + this.stats.rateLimitViolations + ', 연결 거부: ' + this.stats.connectionRejections);
    console.log('   [PATTERN] 빠른 재연결: ' + this.stats.rapidReconnects + ', 의심 패턴: ' + this.stats.suspiciousPatterns);
    
    // 활성 IP 수
    const activeIps = this.stats.ipActivity.size;
    console.log('   [IP] 활성 IP: ' + activeIps + '개');
    
    // 가장 활발한 IP (상위 3개)
    if (activeIps > 0) {
      const topIps = [...this.stats.ipActivity.entries()]
        .map(([ip, data]) => ({ ip: this.maskIp(ip), connects: data.connects.length }))
        .sort((a, b) => b.connects - a.connects)
        .slice(0, 3);
      
      if (topIps[0] && topIps[0].connects > 5) {
        console.log('   [TOP] 활발한 IP: ' + topIps.map(x => x.ip + '(' + x.connects + ')').join(', '));
      }
    }
    console.log('');
  },
  
  // 통계 파일 저장
  saveToFile() {
    try {
      const saveData = {
        timestamp: new Date().toISOString(),
        totalConnections: this.stats.totalConnections,
        totalDisconnections: this.stats.totalDisconnections,
        peakConnections: this.stats.peakConnections,
        peakTime: this.stats.peakTime,
        rateLimitViolations: this.stats.rateLimitViolations,
        connectionRejections: this.stats.connectionRejections,
        rapidReconnects: this.stats.rapidReconnects,
        suspiciousPatterns: this.stats.suspiciousPatterns,
        hourlyStats: this.stats.hourlyStats
      };
      
      fs.writeFileSync(WS_MONITOR_FILE, JSON.stringify(saveData, null, 2), 'utf8');
    } catch (err) {
      // 저장 실패해도 무시
    }
  },
  
  // 통계 파일 로드
  loadFromFile() {
    try {
      if (fs.existsSync(WS_MONITOR_FILE)) {
        const data = JSON.parse(fs.readFileSync(WS_MONITOR_FILE, 'utf8'));
        
        // 누적 통계 복원
        this.stats.totalConnections = data.totalConnections || 0;
        this.stats.totalDisconnections = data.totalDisconnections || 0;
        this.stats.peakConnections = data.peakConnections || 0;
        this.stats.peakTime = data.peakTime || null;
        this.stats.rateLimitViolations = data.rateLimitViolations || 0;
        this.stats.connectionRejections = data.connectionRejections || 0;
        this.stats.rapidReconnects = data.rapidReconnects || 0;
        this.stats.suspiciousPatterns = data.suspiciousPatterns || 0;
        
        console.log('[WS-MONITOR] 통계 파일 복원됨 (피크: ' + this.stats.peakConnections + '명)');
        return true;
      }
    } catch (err) {
      // 로드 실패해도 무시
    }
    return false;
  },
  
  // 모니터링 시작
  start() {
    console.log('[WS-MONITOR] WebSocket 보안 모니터링 시작');
    
    // 파일에서 통계 복원
    this.loadFromFile();
    
    // 3분마다 통계 요약 출력
    setInterval(() => {
      this.logSummary();
      this.saveToFile();
      
      // 오래된 IP 데이터 정리 (30분 이상 비활성)
      const thirtyMinAgo = Date.now() - 1800000;
      for (const [ip, data] of this.stats.ipActivity) {
        if (data.connects.length === 0 && data.disconnects.length === 0) {
          if (data.firstSeen < thirtyMinAgo) {
            this.stats.ipActivity.delete(ip);
          }
        }
      }
      
      // 오래된 알림 기록 정리
      const fiveMinAgo = Date.now() - 300000;
      for (const key of Object.keys(this.stats.lastAlerts)) {
        if (this.stats.lastAlerts[key] < fiveMinAgo) {
          delete this.stats.lastAlerts[key];
        }
      }
      
    }, WS_MONITOR_INTERVAL);
    
    console.log('   - 통계 출력 주기: 3분');
    console.log('   - 빠른 재연결 감지: 10초 내 3회');
    console.log('   - 반복 위반자 감지: 10분 내 5회');
  }
};

// ---
//  HTTP Rate Limit Store (server264)
// - 분당 200회 제한 (server264: 120→200 상향)
// - 버스트 허용: 초당 20회까지 허용
// - 프리페칭(7개 TF 동시 요청) 호환
// ---
const httpRateStore = new Map();
const HTTP_RATE_LIMIT = 200;           // 분당 최대 요청 수
const HTTP_RATE_WINDOW = 60000;        // 1분 (ms)
const HTTP_BURST_LIMIT = 20;           // 초당 버스트 허용
const HTTP_BURST_WINDOW = 1000;        // 1초 (ms)

// 1분마다 만료된 Rate Limit 기록 정리 (메모리 누수 방지)
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of httpRateStore) {
    if (now - data.windowStart > HTTP_RATE_WINDOW) {
      httpRateStore.delete(ip);
    }
  }
}, 60000);

// ---
//  보안 헤더 + Rate Limit 미들웨어 (server264)
// - 기존: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy
// - 추가: HSTS (HTTPS 강제), HTTP Rate Limit (DDoS 방어)
// ---
app.use((req, res, next) => {
  // 기존 보안 헤더
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // HSTS (HTTPS 환경에서만 적용)
  // - Railway, Cloudflare 등 reverse proxy 환경 대응
  // - max-age=15552000 = 180일
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  }

  // HTTP Rate Limit (분당 200회 + 초당 버스트 20회)
  const ip = getClientIp(req);
  const now = Date.now();
  let record = httpRateStore.get(ip);

  if (!record || now - record.windowStart > HTTP_RATE_WINDOW) {
    // 새 윈도우 시작
    record = {
      count: 1,
      windowStart: now,
      burstCount: 1,
      burstStart: now
    };
    httpRateStore.set(ip, record);
  } else {
    // 분당 카운트 증가
    record.count++;

    // 버스트 윈도우 체크
    if (now - record.burstStart > HTTP_BURST_WINDOW) {
      // 새 버스트 윈도우
      record.burstCount = 1;
      record.burstStart = now;
    } else {
      record.burstCount++;
    }

    // 버스트 제한 체크 (초당 20회 초과 시)
    if (record.burstCount > HTTP_BURST_LIMIT) {
      console.warn('[RATE] HTTP Burst Limit exceeded: ' + ip + ' (' + record.burstCount + '/' + HTTP_BURST_LIMIT + '/sec)');
      return res.status(429).json({ ok: false, error: 'burst_limit_exceeded' });
    }

    // 분당 제한 체크
    if (record.count > HTTP_RATE_LIMIT) {
      console.warn('[RATE] HTTP Rate Limit exceeded: ' + ip + ' (' + record.count + '/' + HTTP_RATE_LIMIT + '/min)');
      return res.status(429).json({ ok: false, error: 'rate_limit_exceeded' });
    }
  }

  next();
});

// ---
//  멀티 타임프레임 캔들 아카이빙 시스템
// - 8개 타임프레임: 1m, 3m, 5m, 10m, 15m, 30m, 1h, 4h
// - 각 타임프레임별 40,000개 캔들 한도 (FIFO)
// - 1분봉에서 상위 타임프레임 자동 합성
// - 백그라운드 과거 데이터 수집
// ---
const ARCHIVE_DIR = path.join(DATA_DIR, 'archive');
const ARCHIVE_FLUSH_INTERVAL = 60000;  // 1분마다 버퍼 flush (ms)

//  멀티 타임프레임 설정
const ARCHIVE_TIMEFRAMES = ['1m', '3m', '5m', '10m', '15m', '30m', '1h', '4h'];
//  메모리 절약: 40000 → 2000 (약 33시간치, 모멘텀 계산에 충분)
const ARCHIVE_MAX_CANDLES = 500;  //  메모리 최적화: 2000 → 500

// 타임프레임별 분 단위 변환
const TF_MINUTES = {
  '1m': 1,
  '3m': 3,
  '5m': 5,
  '10m': 10,
  '15m': 15,
  '30m': 30,
  '1h': 60,
  '4h': 240
};

// Archive 디렉토리 및 타임프레임별 서브디렉토리 생성
if (!fs.existsSync(ARCHIVE_DIR)) {
  try {
    fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
    console.log('[DIR]  Archive 디렉토리 생성: ' + ARCHIVE_DIR);
  } catch (err) {
    console.error('[ERROR]  Archive 디렉토리 생성 실패:', err.message);
  }
}

// 타임프레임별 서브디렉토리 생성
for (const tf of ARCHIVE_TIMEFRAMES) {
  const tfDir = path.join(ARCHIVE_DIR, tf);
  if (!fs.existsSync(tfDir)) {
    try {
      fs.mkdirSync(tfDir, { recursive: true });
    } catch (err) {
      // 무시 (이미 존재하거나 권한 문제)
    }
  }
}

const EXCHANGE_RATE_CACHE_FILE = path.join(DATA_DIR, 'exchange_rate.json');
const CACHE_EXPIRY_MS = 24 * 60 * 60 * 1000;  //  24시간 (86400000ms)

const ExchangeRateManager = {
  // 현재 환율 (1 USDT = ? KRW)
  rate: 1450,  // 기본값 (API 실패 시 폴백)
  lastKnownRate: 1450,  //  마지막으로 유효했던 환율 (이상치 판별용)
  lastUpdate: null,
  updateInterval: null,
  
  //  파일에서 환율 로드 (유효성 검사 포함)
  loadFromFile() {
    try {
      // 1. 파일 존재 확인
      if (!fs.existsSync(EXCHANGE_RATE_CACHE_FILE)) {
        console.log('[INFO] [ExchangeRateManager] 캐시 파일 없음 → 기본값 사용: 1 USDT = ' + this.rate.toLocaleString() + ' KRW');
        return false;
      }
      
      // 2. 파일 읽기 및 파싱
      const fileContent = fs.readFileSync(EXCHANGE_RATE_CACHE_FILE, 'utf8');
      let data;
      
      try {
        data = JSON.parse(fileContent);
      } catch (parseError) {
        console.warn('[WARN] [ExchangeRateManager] 캐시 파일 JSON 파싱 실패 (손상된 파일) → 기본값 사용');
        return false;
      }
      
      // 3. 필수 필드 검증
      if (!data || typeof data.rate !== 'number' || data.rate <= 0) {
        console.warn('[WARN] [ExchangeRateManager] 캐시 파일 형식 오류 (rate 없음) → 기본값 사용');
        return false;
      }
      
      // 4.  유효성 검사: timestamp 확인
      if (!data.timestamp || typeof data.timestamp !== 'number') {
        console.warn('[WARN] [ExchangeRateManager] 캐시 파일에 timestamp 없음 → 기본값 사용 (구버전 호환)');
        return false;
      }
      
      const now = Date.now();
      const age = now - data.timestamp;
      const ageHours = (age / (1000 * 60 * 60)).toFixed(1);
      
      if (age > CACHE_EXPIRY_MS) {
        // 만료됨!
        console.warn('[WARN] [ExchangeRateManager] 캐시 만료됨 (Expired)! 저장 후 ' + ageHours + '시간 경과 → 기본값 사용');
        console.warn('   [INFO] 만료된 데이터: 1 USDT = ' + data.rate.toLocaleString() + ' KRW (폐기됨)');
        return false;
      }
      
      // 5. 유효한 데이터 적용
      this.rate = data.rate;
      this.lastKnownRate = data.lastKnownRate || data.rate;
      this.lastUpdate = data.lastUpdate ? new Date(data.lastUpdate) : null;
      
      console.log('[OK] [ExchangeRateManager] 캐시 파일 로드 성공!');
      console.log('   [RATE] 환율: 1 USDT = ' + this.rate.toLocaleString() + ' KRW');
      console.log('   [TIME] 저장 후 ' + ageHours + '시간 경과 (유효: 24시간 이내)');
      
      return true;
      
    } catch (error) {
      // 예상치 못한 오류 (파일 권한 문제 등)
      console.error('[ERROR] [ExchangeRateManager] 캐시 파일 로드 중 예외 발생:', error.message);
      console.log('   [INFO] 기본값 사용: 1 USDT = ' + this.rate.toLocaleString() + ' KRW');
      return false;
    }
  },
  
  //  파일에 환율 저장 (timestamp 포함)
  saveToFile() {
    try {
      const now = Date.now();
      const data = {
        rate: this.rate,
        lastKnownRate: this.lastKnownRate,
        timestamp: now,  //  핵심! 저장 시각 (밀리초)
        lastUpdate: this.lastUpdate ? this.lastUpdate.toISOString() : null,
        savedAt: new Date(now).toISOString()  // 사람이 읽을 수 있는 형태 (디버깅용)
      };
      
      fs.writeFileSync(EXCHANGE_RATE_CACHE_FILE, JSON.stringify(data, null, 2), 'utf8');
      console.log('[SAVE] [ExchangeRateManager] 캐시 파일 저장: 1 USDT = ' + this.rate.toLocaleString() + ' KRW');
      
    } catch (error) {
      // 파일 쓰기 실패해도 서버는 계속 동작
      console.error('[ERROR] [ExchangeRateManager] 캐시 파일 저장 실패:', error.message);
    }
  },
  
  //  초기화 - 파일에서 즉시 로드 후, API는 백그라운드 실행
  initialize() {
    console.log('[RATE] [ExchangeRateManager] 초기화 시작 (파일 캐시 우선 모드)...');
    
    // 1단계: 파일에서 즉시 로드 (동기식 - 블로킹 없음)
    this.loadFromFile();
    
    // 2단계: API 호출은 백그라운드에서 비동기 실행 (Fire-and-forget)
    // - await 없이 실행하여 서버 시작 지연 방지
    this.fetchRates().then(newRate => {
      if (newRate) {
        this.rate = newRate;
        this.lastKnownRate = newRate;
        this.lastUpdate = new Date();
        this.saveToFile();  //  성공 시 파일 저장
        console.log('[OK] [ExchangeRateManager] API 갱신 완료: 1 USDT = ' + this.rate.toLocaleString() + ' KRW');
      }
    }).catch(error => {
      console.warn('[WARN] [ExchangeRateManager] API 초기 갱신 실패 (캐시 사용 중):', error.message);
    });
    
    // 3단계: 1분 간격 폴링 시작
    this.startPolling();
    
    console.log('[START] [ExchangeRateManager] 초기화 즉시 완료! (현재 환율: ' + this.rate.toLocaleString() + ' KRW)');
  },
  
  //  교차 검증 환율 조회
  async fetchRates() {
    let upbitRate = null;
    let bithumbRate = null;
    
    // 병렬 호출 (Promise.all)
    try {
      const [upbitRes, bithumbRes] = await Promise.all([
        axios.get('https://api.upbit.com/v1/ticker?markets=KRW-USDT', {
          timeout: 10000,
          headers: { 'Accept': 'application/json' }
        }).catch(e => null),
        axios.get('https://api.bithumb.com/public/ticker/USDT_KRW', {
          timeout: 10000,
          headers: { 'Accept': 'application/json' }
        }).catch(e => null)
      ]);
      
      // 업비트 파싱
      if (upbitRes && upbitRes.data && upbitRes.data.length > 0) {
        upbitRate = upbitRes.data[0].trade_price;
      }
      
      // 빗썸 파싱 (구조: { status: "0000", data: { closing_price: "1495" } })
      if (bithumbRes && bithumbRes.data && bithumbRes.data.status === '0000') {
        const bithumbData = bithumbRes.data.data;
        if (bithumbData && bithumbData.closing_price) {
          bithumbRate = parseFloat(bithumbData.closing_price);
        }
      }
      
      console.log('[DATA] [환율 조회] 업비트: ' + (upbitRate || 'N/A') + ', 빗썸: ' + (bithumbRate || 'N/A'));
      
      // 산출 로직
      if (upbitRate && bithumbRate) {
        // 둘 다 유효할 때
        const diffPercent = Math.abs((upbitRate - bithumbRate) / upbitRate * 100);
        
        if (diffPercent < 3) {
          // 차이 3% 미만: 평균값 사용
          const avgRate = (upbitRate + bithumbRate) / 2;
          console.log('[RATE] [교차검증] 차이 ' + diffPercent.toFixed(2) + '% (정상) → 평균값 사용: ' + avgRate.toFixed(0));
          return avgRate;
        } else {
          // 차이 3% 이상: lastKnownRate와 더 가까운 값 선택 (이상치 배제)
          const upbitDiff = Math.abs(upbitRate - this.lastKnownRate);
          const bithumbDiff = Math.abs(bithumbRate - this.lastKnownRate);
          
          if (upbitDiff < bithumbDiff) {
            console.log('[WARN] [교차검증] 차이 ' + diffPercent.toFixed(2) + '% (이상!) → 업비트 채택 (빗썸 이상치 의심)');
            return upbitRate;
          } else {
            console.log('[WARN] [교차검증] 차이 ' + diffPercent.toFixed(2) + '% (이상!) → 빗썸 채택 (업비트 이상치 의심)');
            return bithumbRate;
          }
        }
      } else if (upbitRate) {
        // 업비트만 응답
        console.log('[RATE] [환율] 업비트만 응답: ' + upbitRate);
        return upbitRate;
      } else if (bithumbRate) {
        // 빗썸만 응답
        console.log('[RATE] [환율] 빗썸만 응답: ' + bithumbRate);
        return bithumbRate;
      } else {
        // 둘 다 실패
        console.warn('[WARN] [환율] 둘 다 실패! lastKnownRate 유지: ' + this.lastKnownRate);
        return null;
      }
    } catch (error) {
      console.error('[ERROR] [환율 조회 실패]:', error.message);
      return null;
    }
  },
  
  // 주기적 폴링으로 환율 갱신 (1분 간격)
  startPolling() {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
    }
    
    //  1분(60000ms)마다 환율 갱신
    this.updateInterval = setInterval(async () => {
      await this.updateRate();
    }, 60000);
    
    console.log('[SYNC] [ExchangeRateManager] 1분 주기 갱신 시작 (교차 검증 모드)');
  },
  
  // 환율 갱신
  async updateRate() {
    try {
      const newRate = await this.fetchRates();
      
      if (newRate && newRate > 0) {
        const oldRate = this.rate;
        this.rate = newRate;
        this.lastKnownRate = newRate;  //  유효한 값 저장
        this.lastUpdate = new Date();
        
        //  갱신 성공 시 파일 저장
        this.saveToFile();
        
        // 1% 이상 변동 시 로그 및 클라이언트 브로드캐스트
        const changePercent = Math.abs((newRate - oldRate) / oldRate * 100);
        if (changePercent >= 1) {
          console.log('[RATE] [ExchangeRateManager] 환율 변동: ' + oldRate.toLocaleString() + ' → ' + newRate.toLocaleString() + ' KRW (' + changePercent.toFixed(2) + '%)');
          //  환율 변경을 클라이언트에게 브로드캐스트
          broadcastExchangeRate(newRate);
        }
      }
    } catch (error) {
      console.error('[WARN] [ExchangeRateManager] 갱신 실패:', error.message);
    }
  },
  
  // WebSocket 틱으로 환율 업데이트 (실시간)
  updateFromTick(price) {
    if (price && price > 0) {
      this.rate = price;
      this.lastKnownRate = price;
      this.lastUpdate = new Date();
      //  틱 업데이트 시에도 파일 저장 (단, 너무 자주 저장하지 않도록 debounce 고려 가능)
    }
  },
  
  // USD → KRW 변환
  toKRW(usdPrice) {
    return usdPrice * this.rate;
  },
  
  // KRW → USD 변환
  toUSD(krwPrice) {
    return krwPrice / this.rate;
  },
  
  // 현재 환율 반환
  getRate() {
    return this.rate;
  },
  
  // 상태 정보
  getStatus() {
    return {
      rate: this.rate,
      lastKnownRate: this.lastKnownRate,
      lastUpdate: this.lastUpdate,
      isStale: this.lastUpdate ? (Date.now() - this.lastUpdate.getTime() > 300000) : true  // 5분 이상 미갱신 시 stale
    };
  }
};

// ---
// 업비트 24시간 전 가격 캐시 (Trailing 24H 등락률 계산용)
// ---
const upbit24hPriceCache = new Map();  // { symbol: price24hAgo }

// ---
// 다차원 모멘텀 캐시 (명세 2: momentumCacheMap[timeframe][symbol])
// ---
const momentumCacheMap = {
  upbit: {},    // { 1: Map(), 3: Map(), 5: Map(), ... }
  bithumb: {}   // { 1: Map(), 3: Map(), 5: Map(), ... }
};

// ════════════════════════════════════════════════════════════════
//  글로벌 거래소 다차원 모멘텀 캐시
// - 타임프레임별로 글로벌 거래소 모멘텀 저장
// - globalMomentumCache[timeframe].get('BINANCE_SPOT:BTC')
// ════════════════════════════════════════════════════════════════
const globalMomentumCache = {};  // { 1: Map(), 3: Map(), 5: Map(), ... }

// 초기화
[1, 3, 5, 15, 30, 60, 240].forEach(tf => {
  globalMomentumCache[tf] = new Map();
});

// 기존 호환용 (단일 타임프레임 캐시 - 점진적 마이그레이션)
const upbitMomentumCache = new Map();    // 업비트 모멘텀
const bithumbMomentumCache = new Map();  // 빗썸 모멘텀

//  글로벌 거래소 모멘텀 캐시 (기존 호환용)
const binanceSpotMomentumCache = new Map();     // 바이낸스 현물 모멘텀
const binanceFuturesMomentumCache = new Map();  // 바이낸스 선물 모멘텀
const okxSpotMomentumCache = new Map();         // OKX 현물 모멘텀
const okxFuturesMomentumCache = new Map();      // OKX 선물 모멘텀

//  Gap Recovery 플래그 (WebSocket 재연결 감지용)
let upbitWsReconnecting = false;
let bithumbWsReconnecting = false;

// ---
// 빗썸 5분봉 캐시 시스템 (15분봉 합성용)
// ---
const bithumbCandleCache = new Map();
const CANDLE_CACHE_FILE = path.join(DATA_DIR, 'bithumb_candle_cache.json');  //  DATA_DIR 사용
const MAX_CANDLES_PER_SYMBOL = 500;  //  메모리 최적화: 1000 → 500

// ---
//  빗썸 1시간봉 캐시 시스템 (4시간봉 합성용)
// - 4시간봉 = 1시간봉 × 4 합성 (360개 필요 → 1시간봉 1,440개)
// - 5분봉 합성(48:1)은 비효율적 → 1시간봉 합성(4:1)으로 변경
// ---
const bithumb1HourCache = new Map();
const BITHUMB_1HOUR_CACHE_FILE = path.join(DATA_DIR, 'bithumb_1hour_cache.json');
const MAX_1HOUR_CANDLES_PER_SYMBOL = 1500;  // 4시간봉 360개 합성에 1,440개 필요

// ---
// 업비트 24시간 전 가격 캐시 파일 (수정 1: 즉시 표시용)
// ---
const UPBIT_PRICE_CACHE_FILE = path.join(DATA_DIR, 'upbit_price_cache.json');  //  DATA_DIR 사용

// ---
//  CandleManager - 중앙 캔들 매니저
// - 모든 코인의 캔들 데이터를 메모리에서 관리
// - 슬라이딩 윈도우: 최대 10800개 유지 (1주일치)
// - 증분 업데이트 지원 (count=3으로 최신 데이터만 받아서 합침)
// ---
const CANDLE_STORE_FILE = path.join(DATA_DIR, 'upbit_candle_store.json');  //  DATA_DIR 사용
const MULTI_TF_CANDLE_STORE_FILE = path.join(DATA_DIR, 'multi_tf_candle_store.json');  //  Multi-TF 캔들 저장
const GLOBAL_CANDLE_STORE_FILE = path.join(DATA_DIR, 'global_candle_store.json');  //  DATA_DIR 사용
//  메모리 절약: 10800 → 2000 (약 33시간치)
const MAX_CANDLES = 500;  //  메모리 최적화: 2000 → 500 (모멘텀 계산에 360개만 필요)
const INITIAL_BACKFILL_COUNT = 1000;  //  초기 Backfill 요청 개수 (360 → 1000, 바이낸스 최대 지원)
const MOMENTUM_CANDLE_COUNT = 360;   //  모멘텀 계산 기준 캔들 수 (합성된 캔들 기준)
const INCREMENTAL_COUNT = 3;  // 증분 업데이트 시 요청 개수
const BACKFILL_CHUNK_SIZE = 20;  //  병렬 Backfill 청크 크기
const BACKFILL_CHUNK_DELAY = 100;  //  청크 간 딜레이 (ms)

//  Rate Limit 대응 - 거래소별 청크 설정
// - 바이낸스: 분당 1200 weight, klines = 5 weight → 분당 240개 = 초당 4개
// - OKX: 초당 20개 제한 →  더 보수적으로 설정
//  바이낸스 Rate Limit 안전값으로 하향 조정 (418/429 에러 방지)
const BINANCE_CHUNK_SIZE = 3;    //  5개 → 3개 (한 번에 요청 개수 줄임)
const BINANCE_CHUNK_DELAY = 500; //  300ms → 500ms (대기 시간 늘림)
const OKX_CHUNK_SIZE = 5;        //  OKX 5개씩 동시 요청 (3 → 5, 안전 범위 내 속도 개선)
const OKX_CHUNK_DELAY = 1000;    //  OKX 1000ms 딜레이 (500 → 1000)
const CANDLE_SLICE_MULTIPLIER = 500;  //  캔들 합성 전 슬라이스 배율 (timeframe × 500)
const FETCH_RETRY_COUNT = 3;  //  API 요청 재시도 횟수
const FETCH_RETRY_DELAY = 1000;  //  재시도 간 대기 시간 (ms)
const MOMENTUM_CHUNK_SIZE = 50;  //  Phase 3 글로벌 모멘텀 청크 크기
const MOMENTUM_TIMEOUT = 600000;  //  모멘텀 갱신 타임아웃 (3분 → 10분, 전체 타임프레임 완주 보장)

// ---
//  Multi-Timeframe Direct Backfill 상수
// - 각 타임프레임별로 360개 캔들을 직접 API에서 수집
// - 1분봉 합성이 아닌 실제 해당 타임프레임 캔들 사용
// ---
const MULTI_TF_BACKFILL_TIMEFRAMES = [1, 3, 5, 15, 30, 60, 240];  // Backfill할 타임프레임 (10분 제외)
const MIN_CANDLES_FOR_MOMENTUM = 360;  // 모멘텀 계산에 필요한 최소 캔들 수
const MULTI_TF_INCREMENTAL_COUNT = 20;  //  증분 수집 시 요청 개수
const MAX_MULTI_TF_CANDLES = 500;  //  200 → 500 복원 (360개 필요 + 140개 여유분, 200개는 백필 무한반복 유발)

//  API interval 매핑 (우리 타임프레임 → 거래소 API interval)
const BINANCE_INTERVAL_MAP = {
  1: '1m',
  3: '3m',
  5: '5m',
  15: '15m',
  30: '30m',
  60: '1h',
  240: '4h'
};

const OKX_INTERVAL_MAP = {
  1: '1m',
  3: '3m',
  5: '5m',
  15: '15m',
  30: '30m',
  60: '1H',   // OKX는 대문자 H 사용
  240: '4H'
};

//  작업 취소 토큰 (Latest Request Priority)
// - Lock 방식이 아닌, 최신 요청이 이전 요청을 취소하는 방식
// - 버튼 연타 시 이전 작업을 중단하고 최신 작업만 수행
let globalMomentumRequestId = 0;
//  타임프레임별 작업 Lock (동시접속 1000명+ 대응)
// - "First Request Wins" 패턴: 첫 번째 요청만 작업, 이후는 완료 대기
// - 다른 TF와는 독립적으로 병렬 처리 가능
const tfUpdateInProgress = new Map();  // { 5: Promise, 3: Promise, ... }

// ---
//  유틸리티 함수
// ---

/**
 * 배열을 지정된 크기의 청크로 분할
 * @param {Array} array - 분할할 배열
 * @param {number} size - 청크 크기
 * @returns {Array[]} - 청크 배열
 */
function chunkArray(array, size) {
  const chunks = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
}

/**
 * 지정된 시간만큼 대기
 * @param {number} ms - 대기 시간 (밀리초)
 * @returns {Promise}
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 *  재시도 로직이 포함된 API 요청 헬퍼
 * @param {string} url - 요청 URL
 * @param {object} options - axios 옵션 (params 등)
 * @param {number} retries - 재시도 횟수 (기본값: FETCH_RETRY_COUNT)
 * @param {number} delay - 재시도 간 대기 시간 (기본값: FETCH_RETRY_DELAY)
 * @returns {Promise<object|null>} - 성공 시 response, 실패 시 null
 */
async function fetchWithRetry(url, options = {}, retries = FETCH_RETRY_COUNT, delay = FETCH_RETRY_DELAY) {
  let lastError = null;
  
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const response = await axios.get(url, {
        timeout: 10000,
        headers: { 'Accept': 'application/json' },
        ...options
      });
      return response;
    } catch (error) {
      lastError = error;
      
      // 재시도 가능한 에러인지 확인 (네트워크 오류, 429, 5xx)
      const status = error.response?.status;
      const isRetryable = !status || status === 429 || status >= 500;
      
      if (isRetryable && attempt < retries) {
        // 429 에러면 더 긴 대기
        const waitTime = status === 429 ? delay * 2 : delay;
        console.log('   [WARN] [Retry ' + attempt + '/' + retries + '] ' + url.substring(0, 50) + '... (' + waitTime + 'ms 후 재시도)');
        await sleep(waitTime);
      } else if (!isRetryable) {
        // 4xx 에러 (429 제외)는 재시도 안 함
        break;
      }
    }
  }
  
  // 모든 재시도 실패
  if (lastError) {
    const status = lastError.response?.status || 'NETWORK';
    console.log('   [ERROR] [Retry 실패] ' + url.substring(0, 50) + '... (에러: ' + status + ')');
  }
  return null;
}

// ---
//  aggregateCandles - 1분봉을 N분봉으로 합성 (완전 재작성)
// - 입력: 1분봉 배열 (최신순 또는 과거순 상관없이 처리)
// - 출력: N분봉 배열 (최신순 정렬)
// - 로직: timestamp 기준으로 N분 단위 그룹화
// ---
//  메모리 최적화
// - AS-WAS: candles.map(c => ({...c, _ts: ts})) → 전체 복사 (2,300만 객체/cycle)
// - TO-BE: 원본에 _ts만 추가 → 복사 없음
// - forEach → for 루프 변환 (미세 최적화)
// ---
function aggregateCandles(candles, minutes) {
  if (!candles || candles.length === 0) {
    return [];
  }
  
  // 1분봉이면 그대로 반환
  if (minutes <= 1) {
    return candles;
  }
  
  //  1. timestamp 추출 - 복사 없이 원본에 _ts만 추가
  // - 주의: 원본 수정이지만 _ts는 임시 필드이고 다른 곳에서 사용 안 함
  for (let i = 0; i < candles.length; i++) {
    const c = candles[i];
    c._ts = c.timestamp || new Date(c.candle_date_time_utc).getTime();
  }
  
  // 2. 과거순(오름차순) 정렬 - 가장 오래된 캔들이 먼저
  candles.sort((a, b) => a._ts - b._ts);
  
  // 3. N분 단위로 그룹화
  const msPerGroup = minutes * 60 * 1000;
  const groups = new Map();  // groupTimestamp → [candles]
  
  for (let i = 0; i < candles.length; i++) {
    const candle = candles[i];
    const groupTs = Math.floor(candle._ts / msPerGroup) * msPerGroup;
    if (!groups.has(groupTs)) {
      groups.set(groupTs, []);
    }
    groups.get(groupTs).push(candle);
  }
  
  // 4. 각 그룹을 하나의 합성 캔들로 변환
  const aggregated = [];
  
  groups.forEach((groupCandles, groupTs) => {
    // 그룹 내 캔들들은 이미 과거순 정렬됨
    const firstCandle = groupCandles[0];  // 가장 오래된 (Open)
    const lastCandle = groupCandles[groupCandles.length - 1];  // 가장 최신 (Close)
    
    // High: 그룹 내 최고가
    let highPrice = -Infinity;
    // Low: 그룹 내 최저가
    let lowPrice = Infinity;
    
    for (let i = 0; i < groupCandles.length; i++) {
      const c = groupCandles[i];
      const high = c.high_price || c.high || 0;
      const low = c.low_price || c.low || Infinity;
      if (high > highPrice) highPrice = high;
      if (low < lowPrice) lowPrice = low;
    }
    
    // 합성 캔들 생성
    aggregated.push({
      candle_date_time_utc: new Date(groupTs).toISOString(),
      timestamp: groupTs,
      opening_price: firstCandle.opening_price || firstCandle.open,
      high_price: highPrice,
      low_price: lowPrice,
      trade_price: lastCandle.trade_price || lastCandle.close,
      _sourceCount: groupCandles.length
    });
  });
  
  // 5. 최신순(내림차순) 정렬하여 반환
  aggregated.sort((a, b) => b.timestamp - a.timestamp);
  
  return aggregated;
}

// ---
//  MultiTfArchiver - 멀티 타임프레임 캔들 아카이빙 모듈
// - 8개 타임프레임 지원 (1m, 3m, 5m, 10m, 15m, 30m, 1h, 4h)
// - 각 타임프레임별 40,000개 한도 (FIFO)
// - 1분봉에서 상위 타임프레임 자동 합성
// - 중복 방지 로직 (서버 재시작 시에도)
// ---
const MultiTfArchiver = {
  //  store 제거됨 - 메모리 절약 (~900MB)
  // 캔들은 CSV에만 저장, 메모리에는 lastTimestamps만 유지
  // store: {},  // 제거됨
  
  // 타임프레임별 마지막 타임스탬프 (중복 방지)
  // { 'UPBIT_BTC': { '1m': 1732924800000, '5m': 1732924500000, ... }, ... }
  lastTimestamps: {},
  
  // 1분봉 합성용 버퍼: { 'UPBIT_BTC': [candle1, candle2, ...], ... }
  aggregationBuffer: {},
  
  // 디스크 쓰기 버퍼 (flush 전까지 임시 저장)
  writeBuffer: {},
  
  // 통계
  stats: {
    totalArchived: 0,
    lastFlushTime: null,
    flushCount: 0,
    aggregatedCandles: 0
  },
  
  // 파일명 생성
  getFileName(exchange, symbol) {
    const safeExchange = exchange.toUpperCase().replace(/[^A-Z0-9_]/g, '_');
    const safeSymbol = symbol.toUpperCase().replace(/[^A-Z0-9]/g, '');
    return safeExchange + '_' + safeSymbol + '.csv';
  },
  
  // 스토어 키 생성
  getKey(exchange, symbol) {
    return exchange + '_' + symbol;
  },
  
  // 파일 경로 생성 (타임프레임별 폴더)
  getFilePath(exchange, symbol, timeframe) {
    const fileName = this.getFileName(exchange, symbol);
    return path.join(ARCHIVE_DIR, timeframe, fileName);
  },
  
  // 서버 시작 시 기존 CSV 파일들에서 마지막 타임스탬프 로드
  //  store 메모리 저장 제거 - lastTimestamps만 로드
  loadExistingData() {
    //  메모리 최적화: 파일 끝부분만 읽어서 마지막 타임스탬프 추출
    // - AS-WAS: fs.readFileSync(전체 파일) → 수 GB 메모리 스파이크
    // - TO-BE: fs.readSync(끝 512바이트) → 고정 ~6MB (12,200파일 x 512B)
    console.log('[ARCHIVE]  기존 아카이브에서 타임스탬프 로드 시작 (tail-read 최적화)...');
    
    let filesProcessed = 0;
    let skippedEmpty = 0;
    const TAIL_BUFFER_SIZE = 512;  // 마지막 512바이트만 읽기 (CSV 1줄에 충분)
    
    for (const tf of ARCHIVE_TIMEFRAMES) {
      const tfDir = path.join(ARCHIVE_DIR, tf);
      if (!fs.existsSync(tfDir)) continue;
      
      try {
        const files = fs.readdirSync(tfDir).filter(f => f.endsWith('.csv'));
        
        for (const fileName of files) {
          const filePath = path.join(tfDir, fileName);
          const key = fileName.replace('.csv', '');
          
          try {
            //  파일 크기 먼저 확인
            const stat = fs.statSync(filePath);
            if (stat.size === 0) {
              skippedEmpty++;
              continue;
            }
            
            //  파일 끝부분만 읽기
            const fd = fs.openSync(filePath, 'r');
            const readSize = Math.min(TAIL_BUFFER_SIZE, stat.size);
            const buffer = Buffer.alloc(readSize);
            const startPos = Math.max(0, stat.size - readSize);
            
            fs.readSync(fd, buffer, 0, readSize, startPos);
            fs.closeSync(fd);
            
            // 버퍼를 문자열로 변환하고 마지막 라인 추출
            const tail = buffer.toString('utf8');
            const lines = tail.trim().split('\n');
            
            if (lines.length === 0) {
              skippedEmpty++;
              continue;
            }
            
            //  마지막 완전한 라인 추출
            // - 파일 중간부터 읽었으므로 첫 줄은 잘렸을 수 있음
            // - 따라서 마지막 라인(lines[lines.length-1])이 완전한 라인
            const lastLine = lines[lines.length - 1];
            const parts = lastLine.split(',');
            
            if (parts.length >= 1) {
              const lastTs = parseInt(parts[0], 10);
              if (!isNaN(lastTs) && lastTs > 0) {
                if (!this.lastTimestamps[key]) {
                  this.lastTimestamps[key] = {};
                }
                this.lastTimestamps[key][tf] = lastTs;
                filesProcessed++;
              }
            }
            
          } catch (err) {
            // 개별 파일 오류는 무시 (파일 손상, 권한 문제 등)
          }
        }
      } catch (err) {
        console.error('[ARCHIVE] ' + tf + ' 디렉토리 읽기 실패:', err.message);
      }
    }
    
    console.log('[ARCHIVE]  타임스탬프 로드 완료: ' + filesProcessed + '개 파일 (빈 파일 ' + skippedEmpty + '개 스킵)');
  },
  
  // 1분봉 추가 및 상위 타임프레임 합성
  addCandle(exchange, symbol, candle) {
    const key = this.getKey(exchange, symbol);
    
    // 타임스탬프 추출
    let timestamp;
    if (candle.candle_date_time_utc) {
      timestamp = new Date(candle.candle_date_time_utc).getTime();
    } else if (candle.timestamp) {
      timestamp = candle.timestamp;
    } else {
      return;
    }
    
    //  lastTimestamps만 초기화 (store 제거)
    if (!this.lastTimestamps[key]) {
      this.lastTimestamps[key] = {};
    }
    if (!this.aggregationBuffer[key]) {
      this.aggregationBuffer[key] = [];
    }
    
    // 1분봉 정규화
    const normalizedCandle = {
      timestamp: timestamp,
      open: candle.opening_price || candle.open,
      high: candle.high_price || candle.high,
      low: candle.low_price || candle.low,
      close: candle.trade_price || candle.close,
      volume: candle.candle_acc_trade_volume || candle.volume || 0
    };
    
    // 1분봉 저장
    this.addCandleToTimeframe(key, '1m', normalizedCandle);
    
    // 합성 버퍼에 추가
    this.aggregationBuffer[key].push(normalizedCandle);
    
    // 상위 타임프레임 합성 체크
    this.checkAndAggregate(key, timestamp);
  },
  
  // 특정 타임프레임에 캔들 추가 (한도 관리 포함)
  //  store 메모리 저장 제거 → lastTimestamps + writeBuffer만 사용
  addCandleToTimeframe(key, tf, candle) {
    //  lastTimestamps만 초기화 (store 제거)
    if (!this.lastTimestamps[key]) {
      this.lastTimestamps[key] = {};
    }
    
    // 중복 체크
    const lastTs = this.lastTimestamps[key][tf];
    if (lastTs && candle.timestamp <= lastTs) {
      return;  // 이미 있는 캔들 - 스킵
    }
    
    //  store.push 제거 - 메모리 저장 안 함
    // 타임스탬프만 기록 (중복 방지용)
    this.lastTimestamps[key][tf] = candle.timestamp;
    
    // 쓰기 버퍼에 추가 (나중에 flush → CSV 저장)
    this.addToWriteBuffer(key, tf, candle);
  },
  
  // 쓰기 버퍼에 추가
  addToWriteBuffer(key, tf, candle) {
    const bufferKey = key + '_' + tf;
    if (!this.writeBuffer[bufferKey]) {
      this.writeBuffer[bufferKey] = [];
    }
    this.writeBuffer[bufferKey].push(candle);
  },
  
  // 상위 타임프레임 합성 체크
  checkAndAggregate(key, currentTimestamp) {
    const buffer = this.aggregationBuffer[key];
    if (!buffer || buffer.length === 0) return;
    
    // 현재 시간 기준으로 각 타임프레임 체크
    for (const tf of ARCHIVE_TIMEFRAMES) {
      if (tf === '1m') continue;  // 1분봉은 합성 불필요
      
      const minutes = TF_MINUTES[tf];
      const alignedTime = Math.floor(currentTimestamp / (minutes * 60 * 1000)) * (minutes * 60 * 1000);
      
      // 해당 타임프레임 구간에 해당하는 1분봉들 찾기
      const candlesInRange = buffer.filter(c => {
        const candleAlignedTime = Math.floor(c.timestamp / (minutes * 60 * 1000)) * (minutes * 60 * 1000);
        return candleAlignedTime < alignedTime;  // 이전 구간의 캔들
      });
      
      if (candlesInRange.length >= minutes) {
        // 가장 오래된 완성 구간 찾기
        const oldestTs = Math.min(...candlesInRange.map(c => c.timestamp));
        const oldestAligned = Math.floor(oldestTs / (minutes * 60 * 1000)) * (minutes * 60 * 1000);
        
        // 해당 구간의 캔들만 추출
        const toAggregate = candlesInRange.filter(c => {
          const cAligned = Math.floor(c.timestamp / (minutes * 60 * 1000)) * (minutes * 60 * 1000);
          return cAligned === oldestAligned;
        });
        
        if (toAggregate.length > 0) {
          // OHLCV 합성
          const aggregatedCandle = {
            timestamp: oldestAligned,
            open: toAggregate[0].open,
            high: Math.max(...toAggregate.map(c => c.high)),
            low: Math.min(...toAggregate.map(c => c.low)),
            close: toAggregate[toAggregate.length - 1].close,
            volume: toAggregate.reduce((sum, c) => sum + c.volume, 0)
          };
          
          this.addCandleToTimeframe(key, tf, aggregatedCandle);
          this.stats.aggregatedCandles++;
        }
      }
    }
    
    // 오래된 버퍼 정리 (4시간 이상 지난 것)
    const cutoffTime = currentTimestamp - (4 * 60 * 60 * 1000);
    this.aggregationBuffer[key] = buffer.filter(c => c.timestamp > cutoffTime);
  },
  
  // CSV 헤더
  getCSVHeader() {
    return 'timestamp,datetime,open,high,low,close,volume';
  },
  
  // 캔들을 CSV 라인으로 변환
  candleToCSVLine(candle) {
    const datetime = new Date(candle.timestamp).toISOString();
    return [
      candle.timestamp,
      datetime,
      candle.open,
      candle.high,
      candle.low,
      candle.close,
      candle.volume
    ].join(',');
  },
  
  // 쓰기 버퍼를 디스크에 flush
  async flush() {
    const keys = Object.keys(this.writeBuffer);
    if (keys.length === 0) return;
    
    let totalFlushed = 0;
    
    for (const bufferKey of keys) {
      const candles = this.writeBuffer[bufferKey];
      if (!candles || candles.length === 0) continue;
      
      // bufferKey에서 key, tf 분리 (UPBIT_BTC_1m → UPBIT_BTC, 1m)
      const lastUnderscoreIdx = bufferKey.lastIndexOf('_');
      const key = bufferKey.substring(0, lastUnderscoreIdx);
      const tf = bufferKey.substring(lastUnderscoreIdx + 1);
      
      // key에서 exchange, symbol 분리
      const parts = key.split('_');
      let exchange, symbol;
      if (parts.length >= 3) {
        exchange = parts.slice(0, -1).join('_');
        symbol = parts[parts.length - 1];
      } else {
        exchange = parts[0];
        symbol = parts[1];
      }
      
      const filePath = this.getFilePath(exchange, symbol, tf);
      
      try {
        const fileExists = fs.existsSync(filePath);
        
        // 정렬
        candles.sort((a, b) => a.timestamp - b.timestamp);
        
        let csvData = '';
        if (!fileExists) {
          csvData = this.getCSVHeader() + '\n';
        }
        
        for (const candle of candles) {
          csvData += this.candleToCSVLine(candle) + '\n';
        }
        
        fs.appendFileSync(filePath, csvData);
        totalFlushed += candles.length;
        
        this.writeBuffer[bufferKey] = [];
        
      } catch (err) {
        console.error('[ARCHIVE] ' + filePath + ' 저장 실패:', err.message);
      }
    }
    
    if (totalFlushed > 0) {
      this.stats.totalArchived += totalFlushed;
      this.stats.lastFlushTime = Date.now();
      this.stats.flushCount++;
      
      console.log('[ARCHIVE] 캔들 ' + totalFlushed + '개 저장 (누적: ' + this.stats.totalArchived + '개, 합성: ' + this.stats.aggregatedCandles + '개)');
    }
  },
  
  // 파일 한도 관리 (40,000개 초과 시 오래된 것 삭제)
  async trimFiles() {
    for (const tf of ARCHIVE_TIMEFRAMES) {
      const tfDir = path.join(ARCHIVE_DIR, tf);
      if (!fs.existsSync(tfDir)) continue;
      
      try {
        const files = fs.readdirSync(tfDir).filter(f => f.endsWith('.csv'));
        
        for (const fileName of files) {
          const filePath = path.join(tfDir, fileName);
          
          try {
            const content = fs.readFileSync(filePath, 'utf8');
            const lines = content.trim().split('\n');
            
            // 40,000개 초과 시 트림
            if (lines.length > ARCHIVE_MAX_CANDLES + 1) {  // +1 for header
              const header = lines[0];
              const dataLines = lines.slice(-(ARCHIVE_MAX_CANDLES));
              const newContent = header + '\n' + dataLines.join('\n') + '\n';
              fs.writeFileSync(filePath, newContent);
            }
          } catch (err) {
            // 개별 파일 오류 무시
          }
        }
      } catch (err) {
        // 디렉토리 오류 무시
      }
    }
  },
  
  // 상태 조회
  //  store 제거로 lastTimestamps 기반 통계
  getStatus() {
    const coinCount = Object.keys(this.lastTimestamps).length;
    let tfCount = 0;
    for (const key of Object.keys(this.lastTimestamps)) {
      tfCount += Object.keys(this.lastTimestamps[key]).length;
    }
    return {
      coinCount: coinCount,
      timeframeCount: tfCount,
      totalArchived: this.stats.totalArchived,  // CSV에 기록된 캔들
      stats: this.stats,
      writeBufferSize: Object.values(this.writeBuffer).reduce((sum, arr) => sum + arr.length, 0)
    };
  },
  
  // 강제 flush
  async forceFlush() {
    console.log('[ARCHIVE] 서버 종료 전 강제 flush...');
    await this.flush();
  }
};

// ---
//  HistoricalBackfiller - 백그라운드 과거 데이터 수집
// - 서버 시작 시 과거 데이터 최대치 수집
// - 기존 로직에 영향 없이 틈틈이 실행
// - API 리밋 준수 (여유있게)
// ---
const HistoricalBackfiller = {
  // 수집 상태
  isRunning: false,
  currentExchange: null,
  currentSymbolIndex: 0,
  progress: {},
  
  // API 호출 간격 (ms) - 여유있게 설정
  CALL_DELAY: {
    upbit: 200,       // 분당 300회 (안전하게)
    bithumb: 500,     // 초당 2회 (안전하게)
    binance_spot: 100,
    binance_futures: 100,
    okx_spot: 300,    // 초당 3회 (안전하게)
    okx_futures: 300
  },
  
  // 한 번에 수집할 캔들 수 (API당)
  BATCH_SIZE: {
    upbit: 200,
    bithumb: 1440,    // 빗썸은 1일치
    binance_spot: 1000,
    binance_futures: 1000,
    okx_spot: 300,
    okx_futures: 300
  },
  
  // 백그라운드 수집 간격 (ms) - 5분마다 실행
  BACKFILL_INTERVAL: 5 * 60 * 1000,
  
  // 한 번 실행당 최대 API 호출 수 (Rate Limit 보호)
  MAX_CALLS_PER_RUN: 10,
  
  // 초기화
  init() {
    console.log('[BACKFILL] 과거 데이터 수집기 초기화...');
    
    // 진행 상태 초기화
    this.progress = {
      upbit: { completed: [], pending: [], lastRun: null },
      bithumb: { completed: [], pending: [], lastRun: null },
      binance_spot: { completed: [], pending: [], lastRun: null },
      binance_futures: { completed: [], pending: [], lastRun: null },
      okx_spot: { completed: [], pending: [], lastRun: null },
      okx_futures: { completed: [], pending: [], lastRun: null }
    };
  },
  
  // 수집 대상 심볼 설정
  setPendingSymbols(exchange, symbols) {
    if (!this.progress[exchange]) return;
    
    // 이미 완료된 심볼 제외
    const completed = new Set(this.progress[exchange].completed);
    this.progress[exchange].pending = symbols.filter(s => !completed.has(s));
  },
  
  // 백그라운드 수집 실행 (한 번에 조금씩)
  async runBackfill() {
    if (this.isRunning) return;
    this.isRunning = true;
    
    try {
      const exchanges = ['upbit', 'bithumb', 'binance_spot', 'binance_futures', 'okx_spot', 'okx_futures'];
      
      for (const exchange of exchanges) {
        if (!this.progress[exchange]) continue;
        
        const pending = this.progress[exchange].pending;
        if (pending.length === 0) continue;
        
        // 한 번에 MAX_CALLS_PER_RUN개만 처리
        const batch = pending.slice(0, this.MAX_CALLS_PER_RUN);
        let processed = 0;
        
        for (const symbol of batch) {
          try {
            await this.fetchHistoricalCandles(exchange, symbol);
            
            // 완료 처리
            this.progress[exchange].completed.push(symbol);
            this.progress[exchange].pending = this.progress[exchange].pending.filter(s => s !== symbol);
            processed++;
            
            // API 호출 간격
            await this.sleep(this.CALL_DELAY[exchange] || 200);
            
          } catch (err) {
            // 오류 시 다음으로 넘어감
            console.error('[BACKFILL] ' + exchange + '/' + symbol + ' 실패:', err.message);
          }
        }
        
        if (processed > 0) {
          this.progress[exchange].lastRun = Date.now();
          console.log('[BACKFILL] ' + exchange + ': ' + processed + '개 심볼 수집 완료 (남은: ' + this.progress[exchange].pending.length + '개)');
        }
        
        // 거래소당 쉬어가기
        await this.sleep(1000);
      }
      
    } finally {
      this.isRunning = false;
    }
  },
  
  // 과거 캔들 수집 (거래소별)
  async fetchHistoricalCandles(exchange, symbol) {
    const batchSize = this.BATCH_SIZE[exchange] || 200;
    
    switch (exchange) {
      case 'upbit':
        await this.fetchUpbitHistorical(symbol, batchSize);
        break;
      case 'bithumb':
        await this.fetchBithumbHistorical(symbol);
        break;
      case 'binance_spot':
        await this.fetchBinanceSpotHistorical(symbol, batchSize);
        break;
      case 'binance_futures':
        await this.fetchBinanceFuturesHistorical(symbol, batchSize);
        break;
      case 'okx_spot':
        await this.fetchOkxSpotHistorical(symbol, batchSize);
        break;
      case 'okx_futures':
        await this.fetchOkxFuturesHistorical(symbol, batchSize);
        break;
    }
  },
  
  // 업비트 과거 데이터 수집
  async fetchUpbitHistorical(symbol, count) {
    try {
      const response = await axios.get('https://api.upbit.com/v1/candles/minutes/1', {
        params: { market: 'KRW-' + symbol, count: count },
        timeout: 10000
      });
      
      if (response.data && Array.isArray(response.data)) {
        for (const candle of response.data.reverse()) {
          MultiTfArchiver.addCandle('upbit', symbol, candle);
        }
      }
    } catch (err) {
      throw err;
    }
  },
  
  // 빗썸 과거 데이터 수집
  async fetchBithumbHistorical(symbol) {
    try {
      const response = await axios.get('https://api.bithumb.com/public/candlestick/' + symbol + '_KRW/1m', {
        timeout: 10000
      });
      
      if (response.data && response.data.status === '0000' && response.data.data) {
        const candles = response.data.data;
        for (const c of candles) {
          const candle = {
            timestamp: c[0],
            open: parseFloat(c[1]),
            close: parseFloat(c[2]),
            high: parseFloat(c[3]),
            low: parseFloat(c[4]),
            volume: parseFloat(c[5])
          };
          MultiTfArchiver.addCandle('bithumb', symbol, candle);
        }
      }
    } catch (err) {
      throw err;
    }
  },
  
  // 바이낸스 현물 과거 데이터 수집
  async fetchBinanceSpotHistorical(symbol, limit) {
    try {
      const response = await axios.get('https://api.binance.com/api/v3/klines', {
        params: { symbol: symbol + 'USDT', interval: '1m', limit: limit },
        timeout: 10000
      });
      
      if (response.data && Array.isArray(response.data)) {
        for (const k of response.data) {
          const candle = {
            timestamp: k[0],
            open: parseFloat(k[1]),
            high: parseFloat(k[2]),
            low: parseFloat(k[3]),
            close: parseFloat(k[4]),
            volume: parseFloat(k[5])
          };
          MultiTfArchiver.addCandle('binance_spot', symbol, candle);
        }
      }
    } catch (err) {
      throw err;
    }
  },
  
  // 바이낸스 선물 과거 데이터 수집
  async fetchBinanceFuturesHistorical(symbol, limit) {
    try {
      const response = await axios.get('https://fapi.binance.com/fapi/v1/klines', {
        params: { symbol: symbol + 'USDT', interval: '1m', limit: limit },
        timeout: 10000
      });
      
      if (response.data && Array.isArray(response.data)) {
        for (const k of response.data) {
          const candle = {
            timestamp: k[0],
            open: parseFloat(k[1]),
            high: parseFloat(k[2]),
            low: parseFloat(k[3]),
            close: parseFloat(k[4]),
            volume: parseFloat(k[5])
          };
          MultiTfArchiver.addCandle('binance_futures', symbol, candle);
        }
      }
    } catch (err) {
      throw err;
    }
  },
  
  // OKX 현물 과거 데이터 수집
  async fetchOkxSpotHistorical(symbol, limit) {
    try {
      const response = await axios.get('https://www.okx.com/api/v5/market/candles', {
        params: { instId: symbol + '-USDT', bar: '1m', limit: limit },
        timeout: 10000
      });
      
      if (response.data && response.data.code === '0' && response.data.data) {
        for (const k of response.data.data.reverse()) {
          const candle = {
            timestamp: parseInt(k[0], 10),
            open: parseFloat(k[1]),
            high: parseFloat(k[2]),
            low: parseFloat(k[3]),
            close: parseFloat(k[4]),
            volume: parseFloat(k[5])
          };
          MultiTfArchiver.addCandle('okx_spot', symbol, candle);
        }
      }
    } catch (err) {
      throw err;
    }
  },
  
  // OKX 선물 과거 데이터 수집
  async fetchOkxFuturesHistorical(symbol, limit) {
    try {
      const response = await axios.get('https://www.okx.com/api/v5/market/candles', {
        params: { instId: symbol + '-USDT-SWAP', bar: '1m', limit: limit },
        timeout: 10000
      });
      
      if (response.data && response.data.code === '0' && response.data.data) {
        for (const k of response.data.data.reverse()) {
          const candle = {
            timestamp: parseInt(k[0], 10),
            open: parseFloat(k[1]),
            high: parseFloat(k[2]),
            low: parseFloat(k[3]),
            close: parseFloat(k[4]),
            volume: parseFloat(k[5])
          };
          MultiTfArchiver.addCandle('okx_futures', symbol, candle);
        }
      }
    } catch (err) {
      throw err;
    }
  },
  
  // sleep 유틸리티
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  },
  
  // 상태 조회
  getStatus() {
    const status = {};
    for (const exchange of Object.keys(this.progress)) {
      status[exchange] = {
        completed: this.progress[exchange].completed.length,
        pending: this.progress[exchange].pending.length,
        lastRun: this.progress[exchange].lastRun
      };
    }
    return {
      isRunning: this.isRunning,
      exchanges: status
    };
  }
};

//  하위 호환성을 위한 DataArchiver alias
const DataArchiver = {
  addToBuffer(exchange, symbol, candle) {
    MultiTfArchiver.addCandle(exchange, symbol, candle);
  },
  addCandlesToBuffer(exchange, symbol, candles) {
    if (!Array.isArray(candles)) return;
    for (const candle of candles) {
      MultiTfArchiver.addCandle(exchange, symbol, candle);
    }
  },
  async flush() {
    await MultiTfArchiver.flush();
  },
  async forceFlush() {
    await MultiTfArchiver.forceFlush();
  },
  loadExistingTimestamps() {
    MultiTfArchiver.loadExistingData();
  },
  getBufferStatus() {
    return MultiTfArchiver.getStatus();
  }
};

const CandleManager = {
  // 저장소: { upbit: { BTC: { timeframe, candles, updatedAt }, ... }, bithumb: { ... }, ... }
  //  글로벌 거래소 추가
  store: { 
    upbit: {}, 
    bithumb: {},
    binance_spot: {},
    binance_futures: {},
    okx_spot: {},
    okx_futures: {}
  },
  
  // ---
  //  Multi-Timeframe 저장소
  // - 각 타임프레임별 캔들을 직접 저장
  // - 구조: multiTfStore[exchange][symbol][timeframe] = { candles: [...], updatedAt }
  // ---
  multiTfStore: {
    binance_spot: {},
    binance_futures: {},
    okx_spot: {},
    okx_futures: {},
    upbit: {},      //  추가!
    bithumb: {}     //  추가!
  },
  
  //  Multi-Timeframe 캔들 초기화 (Backfill용)
  initializeMultiTfCandles(exchange, symbol, timeframe, candles) {
    if (!this.multiTfStore[exchange]) this.multiTfStore[exchange] = {};
    if (!this.multiTfStore[exchange][symbol]) this.multiTfStore[exchange][symbol] = {};
    
    // 최신순 정렬 (in-place)
    candles.sort((a, b) => {
      const tsA = a.candle_date_time_utc ? new Date(a.candle_date_time_utc).getTime() : a.timestamp;
      const tsB = b.candle_date_time_utc ? new Date(b.candle_date_time_utc).getTime() : b.timestamp;
      return tsB - tsA;  // 최신순 (내림차순)
    });
    
    // 기존 캔들과 병합 (중복 제거)
    const existing = this.multiTfStore[exchange][symbol][timeframe];
    if (existing && existing.candles && existing.candles.length > 0) {
      //  Set 생성 최적화 - 한 번만 순회
      const existingTimestamps = new Set();
      for (let i = 0; i < existing.candles.length; i++) {
        const c = existing.candles[i];
        const ts = c.candle_date_time_utc ? new Date(c.candle_date_time_utc).getTime() : c.timestamp;
        existingTimestamps.add(ts);
      }
      
      //  spread 제거! push로 in-place 병합
      for (let i = 0; i < candles.length; i++) {
        const c = candles[i];
        const ts = c.candle_date_time_utc ? new Date(c.candle_date_time_utc).getTime() : c.timestamp;
        if (!existingTimestamps.has(ts)) {
          existing.candles.push(c);
        }
      }
      
      // in-place 정렬
      existing.candles.sort((a, b) => {
        const tsA = a.candle_date_time_utc ? new Date(a.candle_date_time_utc).getTime() : a.timestamp;
        const tsB = b.candle_date_time_utc ? new Date(b.candle_date_time_utc).getTime() : b.timestamp;
        return tsB - tsA;
      });
      
      //  slice 제거! length 직접 조정 (새 배열 생성 안 함)
      if (existing.candles.length > MAX_MULTI_TF_CANDLES) {
        existing.candles.length = MAX_MULTI_TF_CANDLES;
      }
      
      existing.updatedAt = Date.now();
      
      //  캔들 개수가 충분하면 자동으로 backfilled=true 설정
      if (existing.candles.length >= MIN_CANDLES_FOR_MOMENTUM) {
        existing.backfilled = true;
      }
      
      return existing.candles.length;
    }
    
    // 새로 생성 - 여기서는 slice 필요 (최초 생성이라 복사 불가피)
    // 하지만 length 조정으로 대체 가능
    if (candles.length > MAX_MULTI_TF_CANDLES) {
      candles.length = MAX_MULTI_TF_CANDLES;
    }
    
    this.multiTfStore[exchange][symbol][timeframe] = {
      candles: candles,  //  slice 제거, 원본 배열 직접 사용
      updatedAt: Date.now(),
      //  캔들 개수가 충분하면 자동으로 backfilled=true 설정
      backfilled: candles.length >= MIN_CANDLES_FOR_MOMENTUM
    };
    
    //  기존 데이터 병합 후에도 backfilled 상태 업데이트
    if (this.multiTfStore[exchange][symbol][timeframe].candles.length >= MIN_CANDLES_FOR_MOMENTUM) {
      this.multiTfStore[exchange][symbol][timeframe].backfilled = true;
    }
    
    return candles.length;
  },
  
  //  Multi-Timeframe 캔들 조회
  getMultiTfCandles(exchange, symbol, timeframe) {
    return this.multiTfStore[exchange]?.[symbol]?.[timeframe]?.candles || null;
  },
  
  //  Multi-Timeframe 캔들 개수 조회
  getMultiTfCandleCount(exchange, symbol, timeframe) {
    return this.multiTfStore[exchange]?.[symbol]?.[timeframe]?.candles?.length || 0;
  },
  
  //  Multi-Timeframe 캔들 충분 여부 확인 (n=359 이상)
  hasEnoughMultiTfCandles(exchange, symbol, timeframe) {
    const count = this.getMultiTfCandleCount(exchange, symbol, timeframe);
    return count >= MIN_CANDLES_FOR_MOMENTUM;
  },
  
  // ---
  //  Backfilled 플래그 관리 (초기 로딩 상태 판별용)
  // - backfilled = true: 데이터 수집 완료 (부족하면 "-" 표시)
  // - backfilled = false/undefined: 수집 중 ("Calc..." 표시)
  // ---
  setBackfilled(exchange, symbol, timeframe, value = true) {
    if (!this.multiTfStore[exchange]) this.multiTfStore[exchange] = {};
    if (!this.multiTfStore[exchange][symbol]) this.multiTfStore[exchange][symbol] = {};
    if (!this.multiTfStore[exchange][symbol][timeframe]) {
      this.multiTfStore[exchange][symbol][timeframe] = { candles: [], updatedAt: Date.now() };
    }
    this.multiTfStore[exchange][symbol][timeframe].backfilled = value;
  },
  
  isBackfilled(exchange, symbol, timeframe) {
    return this.multiTfStore[exchange]?.[symbol]?.[timeframe]?.backfilled === true;
  },
  
  // ---
  //  캐시 신선도 판정 (유동적 증분 수집!)
  // ---
  //   updatedAfterClose 조건 때문에 서버 재시작 시 모든 캐시가 "노후" 판정
  //   → cacheUpdatedAt < currentCandleStart
  //   → 캔들 500개 있어도 7968개 심볼x타임프레임 전부 백필
  //   → p50 = 20-30초, 백필 완료까지 몇 시간!
  //   1. updatedAfterClose 조건 제거 → hasLatestCandle만으로 신선도 판정
  //   2. usable 플래그 추가 → 360개 이상이면 즉시 모멘텀 계산 가능
  //   3. neededCandles 유동 계산 → 마지막 캔들부터 현재까지 누락분만 수집
  //      - 서버 1분 다운: 0~1개 수집
  //      - 서버 2시간 다운: 40개 수집 (3분봉 기준)
  // [QA 테스트 케이스]
  //   1. 서버 1분 내 재시작:
  //      - hasLatestCandle = true → 신선! → 증분 수집 불필요
  //   2. 서버 2시간 다운:
  //      - 3분봉: candlesBehind = 40 → neededCandles = 42
  //      - 42개만 증분 수집 → 즉시 완료
  //   3. 봉 마감 직전 종료 → 직후 재시작:
  //      - hasLatestCandle로 판정 (최신 봉 존재 여부)
  //      - 종가 미확정? → WebSocket이 실시간 갱신하므로 OK
  // ---
  isCacheFresh(exchange, symbol, timeframe) {
    const data = this.multiTfStore[exchange]?.[symbol]?.[timeframe];
    if (!data || !data.candles || data.candles.length === 0) {
      return { 
        fresh: false,
        usable: false,  //  캐시 없으면 모멘텀 계산 불가
        candleCount: 0, 
        neededCandles: MIN_CANDLES_FOR_MOMENTUM, 
        reason: 'NO_CACHE',
        secondsBehind: Number.POSITIVE_INFINITY,
        fastEligible: false
      };
    }
    
    const candles = data.candles;
    const candleCount = candles.length;
    //  cacheUpdatedAt 변수 제거 (updatedAfterClose 조건 삭제로 불필요)
    
    // 최신 캔들의 timestamp 확인 (candles[0]이 가장 최신)
    const lastCandle = candles[0];
    const lastCandleTimestamp = lastCandle.candle_date_time_utc 
      ? new Date(lastCandle.candle_date_time_utc).getTime() 
      : lastCandle.timestamp;
    
    const now = Date.now();
    const tfMs = timeframe * 60 * 1000;  // 타임프레임을 밀리초로
    
    //  secondsBehind: 디버깅 및 정렬용
    const secondsBehind = Math.max(0, Math.round((now - lastCandleTimestamp) / 1000));
    
    // 360개 미만이면 무조건 증분 필요
    if (candleCount < MIN_CANDLES_FOR_MOMENTUM) {
      //  누락분도 계산에 포함
      const candlesBehind = Math.max(1, Math.ceil((now - lastCandleTimestamp) / tfMs));
      const neededForCount = MIN_CANDLES_FOR_MOMENTUM - candleCount;
      return { 
        fresh: false,
        usable: false,  //  360개 미만이면 모멘텀 계산 불가
        candleCount: candleCount, 
        neededCandles: neededForCount + candlesBehind + 2,  // 부족분 + 누락분 + 버퍼
        reason: 'INSUFFICIENT_COUNT',
        secondsBehind,
        fastEligible: false
      };
    }
    
    // 현재 진행 중인 봉의 시작 시점 (= 가장 최근에 완료된 봉의 마감 시점)
    const currentCandleStart = Math.floor(now / tfMs) * tfMs;
    
    // 가장 최근에 완료된 봉의 시작 시점
    const latestCompletedCandleStart = currentCandleStart - tfMs;
    
    // ════════════════════════════════════════════════════════════════
    //  신선도 판정: hasLatestCandle만으로 판단!
    // ════════════════════════════════════════════════════════════════
    // [문제] server217의 updatedAfterClose 조건:
    //   서버 재시작 시 cacheUpdatedAt < currentCandleStart
    //   → 모든 캐시가 "노후" 판정 → 7968개 전부 백필 → 몇 시간 소요!
    // [해결] updatedAfterClose 조건 제거!
    //   - 캔들 360개 이상 + 마지막 캔들이 최신 봉에 해당 → 신선!
    //   - 누락된 캔들만 유동적으로 증분 수집
    // ════════════════════════════════════════════════════════════════
    
    // 캐시에 최신 완료 봉이 존재하는가?
    const hasLatestCandle = lastCandleTimestamp >= latestCompletedCandleStart;
    
    //  신선도 = 최신 봉 존재 여부 (updatedAfterClose 조건 제거!)
    const isFresh = hasLatestCandle;
    
    //  neededCandles 유동 계산 (서버 다운 시간에 따라!)
    let neededCandles = 0;
    let reason = 'FRESH';
    
    if (!hasLatestCandle) {
      // 마지막 캔들부터 현재까지 누락된 봉 개수 계산
      const candlesBehind = Math.max(1, Math.ceil(
        (latestCompletedCandleStart - lastCandleTimestamp) / tfMs
      ));
      neededCandles = candlesBehind + 2;  // 누락분 + 버퍼
      reason = 'STALE_MISSING_CANDLES';
    }
    //  STALE_NOT_UPDATED_AFTER_CLOSE 케이스 제거!
    // → 캔들이 있고 최신이면 바로 신선 판정
    
    //  fastEligible: 신선하고 + 120초 이내면 즉시 표시 OK
    const fastEligible = isFresh && secondsBehind <= 120;
    
    return {
      fresh: isFresh,
      usable: true,  //  360개 이상이면 항상 사용 가능
      candleCount: candleCount,
      neededCandles: neededCandles,
      lastCandleTime: lastCandleTimestamp,
      latestRequired: latestCompletedCandleStart,
      reason: reason,
      secondsBehind,
      fastEligible,
      hasLatestCandle
      //  cacheUpdatedAt, lastCandleCloseTime, updatedAfterClose 제거
    };
  },
  
  //  거래소의 모든 심볼 신선도 분석
  // - fresh: 신선 (즉시 표시 가능, usable=true 보장)
  // - stale: 노후 (증분 수집 필요, usable=true일 수 있음)
  // - missing: 캐시 없음 (전체 수집 필요)
  // - stale은 증분 필요량 + 신선도 순 정렬
  analyzeCacheFreshness(exchange, symbols, timeframe) {
    const fresh = [];      // 신선 (즉시 표시 가능)
    const stale = [];      // 노후 (증분 수집 필요)
    const missing = [];    // 캐시 없음 (전체 수집 필요)
    
    //  디버그: reason별 카운트
    const reasonCounts = {};
    
    for (const symbol of symbols) {
      const result = this.isCacheFresh(exchange, symbol, timeframe);
      
      //  reason 카운트
      reasonCounts[result.reason] = (reasonCounts[result.reason] || 0) + 1;
      
      if (result.reason === 'NO_CACHE') {
        missing.push({ symbol, ...result });
      } else if (result.fresh || result.fastEligible) {
        //  신선하거나 fastEligible이면 즉시 표시 가능
        fresh.push({ symbol, ...result });
      } else if (result.usable) {
        //  usable=true지만 fresh=false → 백그라운드 증분 수집
        stale.push({ symbol, ...result });
      } else {
        // usable=false (360개 미만) → stale로 분류
        stale.push({ symbol, ...result });
      }
    }
    
    //  디버그: 분석 결과 상세 로그
    console.log('   [DEBUG] ' + exchange + ' ' + timeframe + '분봉 신선도 분석:');
    console.log('      총 심볼: ' + symbols.length + '개');
    console.log('      fresh: ' + fresh.length + ', stale: ' + stale.length + ', missing: ' + missing.length);
    console.log('      reason 분포: ' + JSON.stringify(reasonCounts));
    
    //  missing이 많으면 캐시 문제 경고
    if (missing.length > symbols.length * 0.5) {
      console.log('      [WARN] missing이 50% 초과! 캐시 로드 실패 가능성');
    }
    
    //  stale 중 INSUFFICIENT_COUNT가 많으면 경고
    const insufficientCount = stale.filter(s => s.reason === 'INSUFFICIENT_COUNT').length;
    if (insufficientCount > 0) {
      console.log('      [WARN] INSUFFICIENT_COUNT(360개 미만): ' + insufficientCount + '개');
      // 샘플 출력
      const samples = stale.filter(s => s.reason === 'INSUFFICIENT_COUNT').slice(0, 3);
      for (let i = 0; i < samples.length; i++) {
        console.log('         ' + samples[i].symbol + ': candleCount=' + samples[i].candleCount + ', needed=' + samples[i].neededCandles);
      }
    }
    
    //  stale은 증분 필요량 오름차순 + 신선도 순 정렬
    stale.sort((a, b) => {
      if (a.neededCandles !== b.neededCandles) {
        return a.neededCandles - b.neededCandles;
      }
      // neededCandles 같으면 secondsBehind 작은 것 우선 (더 신선한 것)
      return (a.secondsBehind || Infinity) - (b.secondsBehind || Infinity);
    });
    
    // missing은 맨 뒤로 (가장 오래 걸림)
    missing.sort((a, b) => a.neededCandles - b.neededCandles);
    
    return { fresh, stale, missing };
  },
  
  //  현재 형성 중인 캔들 (1분봉)
  // { 'binance_spot:BTCUSDT': { open, high, low, close, volume, timestamp } }
  currentCandles: {},
  
  //  틱 기반 캔들 업데이트 (글로벌 거래소용)
  // - 1분 간격으로 캔들 완성
  // - 완성된 캔들은 store에 저장
  // - 반환값: { isNewCandle: boolean, candleCount: number }
  updateFromTick(exchange, symbol, price, timestamp) {
    if (!this.store[exchange]) this.store[exchange] = {};
    
    const key = exchange + ':' + symbol;
    const candleTimestamp = Math.floor(timestamp / 60000) * 60000; // 1분 단위로 정규화
    
    // 현재 형성 중인 캔들 가져오기
    let current = this.currentCandles[key];
    let isNewCandle = false;
    
    if (!current || current.timestamp !== candleTimestamp) {
      // 새 캔들 시작 (이전 캔들 완성)
      if (current) {
        // 이전 캔들 저장
        this.pushCandle(exchange, symbol, current);
        isNewCandle = true;  //  새 캔들 생성됨
      }
      
      // 새 캔들 생성
      this.currentCandles[key] = {
        timestamp: candleTimestamp,
        open: price,
        high: price,
        low: price,
        close: price,
        volume: 0
      };
    } else {
      // 기존 캔들 업데이트
      current.high = Math.max(current.high, price);
      current.low = Math.min(current.low, price);
      current.close = price;
    }
    
    //  캔들 개수 반환 (모멘텀 계산 가능 여부 판단용)
    const candleCount = this.store[exchange]?.[symbol]?.candles?.length || 0;
    
    return { isNewCandle, candleCount };
  },
  
  //  완성된 캔들을 store에 추가
  pushCandle(exchange, symbol, candle) {
    if (!this.store[exchange]) this.store[exchange] = {};
    if (!this.store[exchange][symbol]) {
      this.store[exchange][symbol] = {
        timeframe: 1,  // 1분봉
        candles: [],
        updatedAt: Date.now()
      };
    }
    
    const data = this.store[exchange][symbol];
    
    // 업비트 형식으로 변환 (모멘텀 계산 호환성)
    const formattedCandle = {
      candle_date_time_utc: new Date(candle.timestamp).toISOString(),
      opening_price: candle.open,
      high_price: candle.high,
      low_price: candle.low,
      trade_price: candle.close,
      timestamp: candle.timestamp
    };
    
    //  아카이브에 캔들 추가 (슬라이스 전에 저장)
    DataArchiver.addToBuffer(exchange, symbol, formattedCandle);
    
    // 최신 캔들을 앞에 추가 (업비트 형식: 최신순)
    data.candles.unshift(formattedCandle);
    
    // MAX_CANDLES(43200) 유지 - 30일치
    if (data.candles.length > MAX_CANDLES) {
      data.candles = data.candles.slice(0, MAX_CANDLES);
    }
    
    data.updatedAt = Date.now();
    
    //  200개 도달 시 모멘텀 계산 가능 로그 (Backfill 없이 WebSocket만으로 축적된 경우)
    if (data.candles.length === INITIAL_BACKFILL_COUNT && !data.backfilled) {
      console.log('[DATA] [CandleManager] ' + exchange + ':' + symbol + ' 캔들 ' + INITIAL_BACKFILL_COUNT + '개 도달 - 모멘텀 계산 가능!');
    }
    
    //  1분봉도 multiTfStore에 동기화 (isCacheFresh 호환)
    // - 글로벌 거래소 1분봉이 multiTfStore에 없어서 매 재시작마다 전체 백필되는 문제 해결
    if (!this.multiTfStore[exchange]) this.multiTfStore[exchange] = {};
    if (!this.multiTfStore[exchange][symbol]) this.multiTfStore[exchange][symbol] = {};
    if (!this.multiTfStore[exchange][symbol][1]) {
      this.multiTfStore[exchange][symbol][1] = { candles: [], updatedAt: Date.now() };
    }
    
    const multiTfData = this.multiTfStore[exchange][symbol][1];
    // 최신 캔들을 앞에 추가 (업비트 형식: 최신순)
    multiTfData.candles.unshift(formattedCandle);
    
    // MAX_MULTI_TF_CANDLES 유지
    if (multiTfData.candles.length > MAX_MULTI_TF_CANDLES) {
      multiTfData.candles.length = MAX_MULTI_TF_CANDLES;
    }
    
    multiTfData.updatedAt = Date.now();
    
    // 360개 이상이면 backfilled 상태로 표시
    if (multiTfData.candles.length >= MIN_CANDLES_FOR_MOMENTUM) {
      multiTfData.backfilled = true;
    }
  },
  
  //  Backfill 초기화: REST API에서 가져온 과거 캔들 적재
  initializeFromBackfill(exchange, symbol, candles) {
    if (!this.store[exchange]) this.store[exchange] = {};
    
    // 이미 데이터가 있으면 병합, 없으면 새로 생성
    if (!this.store[exchange][symbol]) {
      this.store[exchange][symbol] = {
        timeframe: 1,  // 1분봉
        candles: [],
        updatedAt: Date.now(),
        backfilled: true
      };
    }
    
    const data = this.store[exchange][symbol];
    
    // Backfill 캔들 추가 (최신순 정렬)
    // API 응답이 최신순인지 확인하고, 아니면 정렬
    const sortedCandles = candles.sort((a, b) => {
      const tsA = a.candle_date_time_utc ? new Date(a.candle_date_time_utc).getTime() : a.timestamp;
      const tsB = b.candle_date_time_utc ? new Date(b.candle_date_time_utc).getTime() : b.timestamp;
      return tsB - tsA;  // 최신순 (내림차순)
    });
    
    // 기존 캔들과 병합 (중복 제거)
    const existingTimestamps = new Set(data.candles.map(c => {
      return c.candle_date_time_utc ? new Date(c.candle_date_time_utc).getTime() : c.timestamp;
    }));
    
    const newCandles = sortedCandles.filter(c => {
      const ts = c.candle_date_time_utc ? new Date(c.candle_date_time_utc).getTime() : c.timestamp;
      return !existingTimestamps.has(ts);
    });
    
    //  새로운 캔들들을 아카이브에 추가 (슬라이스 전에 저장)
    DataArchiver.addCandlesToBuffer(exchange, symbol, newCandles);
    
    //  spread 제거! push로 in-place 병합
    for (let i = 0; i < newCandles.length; i++) {
      data.candles.push(newCandles[i]);
    }
    
    // 최신순 재정렬 (in-place)
    data.candles.sort((a, b) => {
      const tsA = a.candle_date_time_utc ? new Date(a.candle_date_time_utc).getTime() : a.timestamp;
      const tsB = b.candle_date_time_utc ? new Date(b.candle_date_time_utc).getTime() : b.timestamp;
      return tsB - tsA;
    });
    
    //  slice 제거! length 직접 조정
    if (data.candles.length > MAX_CANDLES) {
      data.candles.length = MAX_CANDLES;
    }
    
    data.updatedAt = Date.now();
    data.backfilled = true;
    
    //  1분봉도 multiTfStore에 동기화 (isCacheFresh 호환)
    // - store에 저장된 1분봉을 multiTfStore에도 복사
    this.syncOneMinToMultiTf(exchange, symbol);
    
    return data.candles.length;
  },
  
  //  글로벌 거래소 캔들 개수 확인
  getGlobalCandleCount(exchange, symbol) {
    if (!this.store[exchange] || !this.store[exchange][symbol]) return 0;
    return this.store[exchange][symbol].candles.length;
  },
  
  //  캔들 병합 (기존 데이터 + 새 데이터)
  // - 중복 제거, 최신순 정렬, MAX_CANDLES 제한
  mergeCandles(exchange, symbol, newCandles) {
    if (!this.store[exchange]) this.store[exchange] = {};
    if (!this.store[exchange][symbol]) {
      // 기존 데이터 없으면 initializeFromBackfill 사용
      return this.initializeFromBackfill(exchange, symbol, newCandles);
    }
    
    const data = this.store[exchange][symbol];
    const existingCandles = data.candles || [];
    
    // timestamp 기준 중복 제거
    const existingTimestamps = new Set(existingCandles.map(c => {
      return c.candle_date_time_utc ? new Date(c.candle_date_time_utc).getTime() : c.timestamp;
    }));
    
    const uniqueNewCandles = newCandles.filter(c => {
      const ts = c.candle_date_time_utc ? new Date(c.candle_date_time_utc).getTime() : c.timestamp;
      return !existingTimestamps.has(ts);
    });
    
    //  새로운 캔들들을 아카이브에 추가 (슬라이스 전에 저장)
    DataArchiver.addCandlesToBuffer(exchange, symbol, uniqueNewCandles);
    
    //  spread 제거! push로 in-place 병합
    for (let i = 0; i < uniqueNewCandles.length; i++) {
      existingCandles.push(uniqueNewCandles[i]);
    }
    
    // 최신순 정렬 (in-place)
    existingCandles.sort((a, b) => {
      const tsA = a.candle_date_time_utc ? new Date(a.candle_date_time_utc).getTime() : a.timestamp;
      const tsB = b.candle_date_time_utc ? new Date(b.candle_date_time_utc).getTime() : b.timestamp;
      return tsB - tsA;
    });
    
    //  slice 제거! length 직접 조정
    if (existingCandles.length > MAX_CANDLES) {
      existingCandles.length = MAX_CANDLES;
    }
    data.candles = existingCandles;
    data.updatedAt = Date.now();
    
    //  1분봉도 multiTfStore에 동기화 (isCacheFresh 호환)
    this.syncOneMinToMultiTf(exchange, symbol);
    
    return data.candles.length;
  },
  
  // 초기화: 최초 200개 데이터 적재
  initialize(exchange, symbol, timeframe, candles) {
    if (!this.store[exchange]) this.store[exchange] = {};
    
    // 최신 200개만 유지 (API는 최신순으로 반환)
    const trimmedCandles = candles.slice(0, MAX_CANDLES);
    
    this.store[exchange][symbol] = {
      timeframe: timeframe,
      candles: trimmedCandles,
      updatedAt: Date.now()
    };
    
    return trimmedCandles;
  },
  
  //  1분봉을 store에서 multiTfStore로 동기화
  // - 글로벌 거래소(binance, okx)의 1분봉이 multiTfStore에 없어서
  //   매 재시작마다 730K개의 캔들을 전체 백필하는 문제 해결
  // - isCacheFresh가 multiTfStore에서 1분봉을 찾을 수 있게 함
  syncOneMinToMultiTf(exchange, symbol) {
    const storeData = this.store[exchange]?.[symbol];
    if (!storeData || !storeData.candles || storeData.candles.length === 0) {
      return;
    }
    
    // multiTfStore 구조 초기화
    if (!this.multiTfStore[exchange]) this.multiTfStore[exchange] = {};
    if (!this.multiTfStore[exchange][symbol]) this.multiTfStore[exchange][symbol] = {};
    
    // store의 1분봉 데이터를 multiTfStore[exchange][symbol][1]에 복사
    // - 최대 MAX_MULTI_TF_CANDLES(500)개만 유지
    const candlesToSync = storeData.candles.slice(0, MAX_MULTI_TF_CANDLES);
    
    this.multiTfStore[exchange][symbol][1] = {
      candles: candlesToSync,
      updatedAt: Date.now(),
      backfilled: candlesToSync.length >= MIN_CANDLES_FOR_MOMENTUM
    };
  },
  
  // 증분 업데이트: 새 캔들을 합치고 200개로 유지
  update(exchange, symbol, timeframe, newCandles) {
    if (!this.store[exchange]) this.store[exchange] = {};
    
    const existing = this.store[exchange][symbol];
    
    // 기존 데이터 없으면 초기화 모드로 전환
    if (!existing || !existing.candles || existing.candles.length === 0) {
      return this.initialize(exchange, symbol, timeframe, newCandles);
    }
    
    // 타임프레임 변경 시 기존 데이터 무효화
    if (existing.timeframe !== timeframe) {
      console.log('[SYNC] [CandleManager] 타임프레임 변경 감지 (' + symbol + '): ' + existing.timeframe + ' → ' + timeframe);
      return this.initialize(exchange, symbol, timeframe, newCandles);
    }
    
    // 중복 제거: timestamp 기준 (업비트는 candle_date_time_utc 사용)
    const existingTimestamps = new Set(
      existing.candles.map(c => c.candle_date_time_utc || c.timestamp)
    );
    
    const uniqueNewCandles = newCandles.filter(c => {
      const ts = c.candle_date_time_utc || c.timestamp;
      return !existingTimestamps.has(ts);
    });
    
    // Gap 검출: 새 캔들의 마지막과 기존 캔들의 첫 번째 사이 연속성 확인
    if (uniqueNewCandles.length > 0 && existing.candles.length > 0) {
      // 업비트 캔들은 최신순 정렬 (newCandles[last] 다음이 existing[0] 이어야 함)
      const oldestNew = new Date(uniqueNewCandles[uniqueNewCandles.length - 1].candle_date_time_utc);
      const newestExisting = new Date(existing.candles[0].candle_date_time_utc);
      
      // 예상 간격 (분 단위 * 60 * 1000ms) + 여유 10%
      const expectedGap = timeframe * 60 * 1000 * 1.1;
      const actualGap = oldestNew - newestExisting;
      
      if (actualGap > expectedGap * INCREMENTAL_COUNT) {
        // Gap 발생! 데이터 불연속
        console.warn('[WARN] [CandleManager] Gap 감지 (' + symbol + '): ' + Math.round(actualGap / 60000) + '분 차이 → 재초기화 필요');
        return null;  // null 반환 = 재초기화 필요 신호
      }
    }
    
    //  spread 제거! 새 배열 최소 할당으로 병합
    // - uniqueNewCandles를 앞에 (최신), existing.candles를 뒤에 (과거)
    // - MAX_CANDLES 초과분은 처음부터 제외
    const totalNeeded = Math.min(uniqueNewCandles.length + existing.candles.length, MAX_CANDLES);
    const merged = [];
    for (let i = 0; i < uniqueNewCandles.length && merged.length < totalNeeded; i++) {
      merged.push(uniqueNewCandles[i]);
    }
    for (let i = 0; i < existing.candles.length && merged.length < totalNeeded; i++) {
      merged.push(existing.candles[i]);
    }
    
    this.store[exchange][symbol] = {
      timeframe: timeframe,
      candles: merged,
      updatedAt: Date.now()
    };
    
    return merged;
  },
  
  // 데이터 조회
  get(exchange, symbol) {
    if (!this.store[exchange] || !this.store[exchange][symbol]) {
      return null;
    }
    return this.store[exchange][symbol];
  },
  
  // 데이터 존재 여부 확인
  hasData(exchange, symbol, timeframe) {
    const data = this.get(exchange, symbol);
    if (!data || !data.candles || data.candles.length < 10) return false;
    // 타임프레임이 일치하는지도 확인
    return data.timeframe === timeframe;
  },
  
  // 캔들 개수 확인
  getCandleCount(exchange, symbol) {
    const data = this.get(exchange, symbol);
    return data ? data.candles.length : 0;
  },
  
  // 전체 심볼 수 확인
  getSymbolCount(exchange) {
    return Object.keys(this.store[exchange] || {}).length;
  },
  
  // 파일에 저장
  //  글로벌 거래소 포함 + 파일 크기 제한 (50MB)
  saveToFile() {
    try {
      // ---
      //  파일 저장 전 캔들 수 강제 정리
      // - 1분봉: MAX_CANDLES (10800개 = 1주일치)
      // - 글로벌 거래소: 1000개로 제한 (모멘텀 계산에 충분)
      // ---
      
      // 글로벌 거래소 캔들 정리 (저장 전 항상 수행)
      ['binance_spot', 'binance_futures', 'okx_spot', 'okx_futures'].forEach(ex => {
        if (this.store[ex]) {
          Object.keys(this.store[ex]).forEach(symbol => {
            if (this.store[ex][symbol]?.candles?.length > 1000) {
              this.store[ex][symbol].candles = this.store[ex][symbol].candles.slice(0, 1000);
            }
          });
        }
      });
      
      // 업비트/빗썸 캔들 정리
      ['upbit', 'bithumb'].forEach(ex => {
        if (this.store[ex]) {
          Object.keys(this.store[ex]).forEach(symbol => {
            if (this.store[ex][symbol]?.candles?.length > MAX_CANDLES) {
              this.store[ex][symbol].candles = this.store[ex][symbol].candles.slice(0, MAX_CANDLES);
            }
          });
        }
      });
      
      //  multiTfStore는 저장하지 않음 (서버 재시작 시 Backfill로 복구)
      // 파일 크기를 줄이기 위해 메인 store만 저장
      const storeToSave = {
        upbit: this.store.upbit,
        bithumb: this.store.bithumb,
        binance_spot: this.store.binance_spot,
        binance_futures: this.store.binance_futures,
        okx_spot: this.store.okx_spot,
        okx_futures: this.store.okx_futures
      };
      
      const jsonData = JSON.stringify(storeToSave);
      const fileSizeMB = jsonData.length / (1024 * 1024);
      
      //  100MB 초과 시 경고 및 추가 정리 (50MB → 100MB로 상향)
      if (fileSizeMB > 100) {
        console.warn('[WARN] [CandleManager] 파일 크기 경고: ' + fileSizeMB.toFixed(2) + 'MB - 추가 정리 수행');
        // 글로벌 거래소 캔들을 500개로 더 제한
        ['binance_spot', 'binance_futures', 'okx_spot', 'okx_futures'].forEach(ex => {
          if (this.store[ex]) {
            Object.keys(this.store[ex]).forEach(symbol => {
              if (this.store[ex][symbol]?.candles?.length > 500) {
                this.store[ex][symbol].candles = this.store[ex][symbol].candles.slice(0, 500);
              }
            });
          }
        });
      }
      
      fs.writeFileSync(CANDLE_STORE_FILE, jsonData, 'utf8');
      
      const upbitCount = this.getSymbolCount('upbit');
      const bithumbCount = this.getSymbolCount('bithumb');
      const binanceSpotCount = this.getSymbolCount('binance_spot');
      const binanceFuturesCount = this.getSymbolCount('binance_futures');
      const okxSpotCount = this.getSymbolCount('okx_spot');
      const okxFuturesCount = this.getSymbolCount('okx_futures');
      
      console.log('[SAVE] [CandleManager] 파일 저장 완료 (' + fileSizeMB.toFixed(2) + 'MB)');
      console.log('   └─ 업비트: ' + upbitCount + '개, 빗썸: ' + bithumbCount + '개');
      console.log('   └─ 바이낸스: ' + binanceSpotCount + '+' + binanceFuturesCount + '개, OKX: ' + okxSpotCount + '+' + okxFuturesCount + '개');
      
      //  Multi-TF 캔들도 함께 저장
      this.saveMultiTfToFile();
    } catch (error) {
      console.error('[ERROR] [CandleManager] 파일 저장 실패:', error.message);
    }
  },
  
  // 파일에서 복원
  //  글로벌 거래소 store 초기화 보장
  loadFromFile() {
    try {
      if (fs.existsSync(CANDLE_STORE_FILE)) {
        const data = fs.readFileSync(CANDLE_STORE_FILE, 'utf8');
        const parsed = JSON.parse(data);
        
        // 구조 검증
        if (parsed && typeof parsed === 'object') {
          //  글로벌 거래소 store 보장
          this.store = {
            upbit: {},
            bithumb: {},
            binance_spot: {},
            binance_futures: {},
            okx_spot: {},
            okx_futures: {}
          };
          
          //  각 심볼별로 backfilled 플래그 조건부 설정
          const exchanges = ['upbit', 'bithumb', 'binance_spot', 'binance_futures', 'okx_spot', 'okx_futures'];
          exchanges.forEach(exchange => {
            if (parsed[exchange]) {
              Object.keys(parsed[exchange]).forEach(symbol => {
                const saved = parsed[exchange][symbol];
                if (saved && saved.candles && saved.candles.length > 0) {
                  const hasEnoughCandles = saved.candles.length >= MIN_CANDLES_FOR_MOMENTUM;
                  this.store[exchange][symbol] = {
                    timeframe: saved.timeframe || 1,
                    candles: saved.candles.slice(0, MAX_CANDLES),
                    updatedAt: saved.updatedAt || Date.now(),
                    backfilled: hasEnoughCandles  //  360개 이상이면 true
                  };
                }
              });
            }
          });
          
          const upbitCount = this.getSymbolCount('upbit');
          const bithumbCount = this.getSymbolCount('bithumb');
          const binanceSpotCount = this.getSymbolCount('binance_spot');
          const okxSpotCount = this.getSymbolCount('okx_spot');
          
          console.log('[DIR] [CandleManager] 파일 복원 완료');
          console.log('   └─ 업비트: ' + upbitCount + '개, 빗썸: ' + bithumbCount + '개');
          console.log('   └─ 바이낸스: ' + binanceSpotCount + '개, OKX: ' + okxSpotCount + '개');
          console.log('[START]  증분 업데이트 모드 활성화 (count=3으로 시작 가능!)');
          return true;
        }
      }
      console.log('[DIR] [CandleManager] 파일 없음 - 초기화 모드 (count=200)');
      return false;
    } catch (error) {
      console.error('[ERROR] [CandleManager] 파일 복원 실패:', error.message);
      return false;
    }
  },
  
  // ---
  //  Multi-TF 캔들 저장/복원 (스마트 증분 수집 핵심!)
  // - 서버 재시작 시 기존 데이터 복원 → 증분 수집만 수행
  // - 파일 크기 최적화: 각 타임프레임당 최대 400개만 저장
  // ---
  
  saveMultiTfToFile() {
    try {
      const MAX_SAVE_CANDLES = 400;  // 저장 시 최대 캔들 수 (360 + 여유분)
      
      // 저장할 데이터 구조 생성 (깊은 복사 + 크기 제한)
      const dataToSave = {};
      const exchanges = ['upbit', 'bithumb', 'binance_spot', 'binance_futures', 'okx_spot', 'okx_futures'];
      
      let totalSymbols = 0;
      let totalCandles = 0;
      
      exchanges.forEach(exchange => {
        if (this.multiTfStore[exchange]) {
          dataToSave[exchange] = {};
          Object.keys(this.multiTfStore[exchange]).forEach(symbol => {
            dataToSave[exchange][symbol] = {};
            Object.keys(this.multiTfStore[exchange][symbol]).forEach(tf => {
              const tfData = this.multiTfStore[exchange][symbol][tf];
              if (tfData && tfData.candles && tfData.candles.length > 0) {
                dataToSave[exchange][symbol][tf] = {
                  candles: tfData.candles.slice(0, MAX_SAVE_CANDLES),
                  updatedAt: tfData.updatedAt || Date.now(),
                  backfilled: tfData.backfilled || false
                };
                totalCandles += Math.min(tfData.candles.length, MAX_SAVE_CANDLES);
                totalSymbols++;
              }
            });
          });
        }
      });
      
      const jsonData = JSON.stringify(dataToSave);
      const fileSizeMB = jsonData.length / (1024 * 1024);
      
      fs.writeFileSync(MULTI_TF_CANDLE_STORE_FILE, jsonData, 'utf8');
      
      console.log('[SAVE]  Multi-TF 캔들 저장 완료 (' + fileSizeMB.toFixed(2) + 'MB, ' + totalSymbols + '개 심볼x타임프레임)');
    } catch (error) {
      console.error('[ERROR]  Multi-TF 캔들 저장 실패:', error.message);
    }
  },
  
  loadMultiTfFromFile() {
    try {
      if (fs.existsSync(MULTI_TF_CANDLE_STORE_FILE)) {
        const data = fs.readFileSync(MULTI_TF_CANDLE_STORE_FILE, 'utf8');
        const parsed = JSON.parse(data);
        
        if (parsed && typeof parsed === 'object') {
          const exchanges = ['upbit', 'bithumb', 'binance_spot', 'binance_futures', 'okx_spot', 'okx_futures'];
          let totalSymbols = 0;
          let totalCandles = 0;
          
          exchanges.forEach(exchange => {
            if (parsed[exchange]) {
              if (!this.multiTfStore[exchange]) {
                this.multiTfStore[exchange] = {};
              }
              
              Object.keys(parsed[exchange]).forEach(symbol => {
                if (!this.multiTfStore[exchange][symbol]) {
                  this.multiTfStore[exchange][symbol] = {};
                }
                
                Object.keys(parsed[exchange][symbol]).forEach(tf => {
                  const saved = parsed[exchange][symbol][tf];
                  if (saved && saved.candles && saved.candles.length > 0) {
                    //  하드코딩 500 → MAX_MULTI_TF_CANDLES 상수 사용으로 일관성 확보
                    // - 모멘텀 계산에 360개 필요 + 여유분 140개
                    const trimmedCandles = saved.candles.slice(-MAX_MULTI_TF_CANDLES);
                    this.multiTfStore[exchange][symbol][tf] = {
                      candles: trimmedCandles,
                      updatedAt: saved.updatedAt || Date.now(),
                      backfilled: trimmedCandles.length >= MIN_CANDLES_FOR_MOMENTUM
                    };
                    totalCandles += trimmedCandles.length;
                    totalSymbols++;
                  }
                });
              });
            }
          });
          
          console.log('[LOAD]  Multi-TF 캔들 복원 완료! (' + totalSymbols + '개 심볼x타임프레임, ' + totalCandles + '개 캔들)');
          console.log('[OK]  메모리 최적화: 파일에서 최신 500개만 로드 (모멘텀 360개 충족)');
          return true;
        }
      }
      console.log('[LOAD]  Multi-TF 캔들 파일 없음 - 전체 수집 모드');
      return false;
    } catch (error) {
      console.error('[ERROR]  Multi-TF 캔들 복원 실패:', error.message);
      return false;
    }
  },
  
  // 기존 upbitCandleCache 호환용 (점진적 마이그레이션)
  migrateFromOldCache(oldCache) {
    if (!oldCache || oldCache.size === 0) return;
    
    let count = 0;
    oldCache.forEach((data, symbol) => {
      if (data && data.candles) {
        this.store.upbit[symbol] = {
          timeframe: data.timeframe || 1,
          candles: data.candles.slice(0, MAX_CANDLES),
          updatedAt: data.updatedAt || Date.now()
        };
        count++;
      }
    });
    
    console.log('[SYNC] [CandleManager] 기존 캐시 마이그레이션 완료: ' + count + '개 심볼');
  },
  
  // ---
  //  틱 기반 캔들 합성 (Zero-Polling 핵심!)
  // ---
  
  // 현재 진행 중인 캔들 저장소 (아직 완성되지 않은 캔들)
  currentCandles: { upbit: {}, bithumb: {} },
  
  // 틱 데이터로 캔들 업데이트
  // 반환값: { isNewCandle: boolean, recalcNeeded: boolean }
  processTick(exchange, symbol, price, timestamp) {
    const timeframe = momentumTimeframe || 1;  // 현재 선택된 타임프레임
    const tickMinute = Math.floor(timestamp / (timeframe * 60 * 1000));
    
    // 현재 캔들 가져오기 (없으면 생성)
    if (!this.currentCandles[exchange]) {
      this.currentCandles[exchange] = {};
    }
    
    let current = this.currentCandles[exchange][symbol];
    
    // 현재 캔들이 없거나 다른 분봉이면 새 캔들 시작
    if (!current || current.minute !== tickMinute) {
      // 이전 캔들이 있으면 완성하여 저장
      if (current && current.minute < tickMinute) {
        this._completeCandle(exchange, symbol, current);
      }
      
      // 새 캔들 시작
      this.currentCandles[exchange][symbol] = {
        minute: tickMinute,
        timestamp: timestamp,
        open: price,
        high: price,
        low: price,
        close: price,
        trade_price: price,
        candle_date_time_utc: new Date(tickMinute * timeframe * 60 * 1000).toISOString()
      };
      
      return { isNewCandle: true, recalcNeeded: current ? true : false };
    }
    
    // 같은 분봉이면 업데이트
    current.high = Math.max(current.high, price);
    current.low = Math.min(current.low, price);
    current.close = price;
    current.trade_price = price;
    
    return { isNewCandle: false, recalcNeeded: false };
  },
  
  // 완성된 캔들을 store에 추가
  _completeCandle(exchange, symbol, candle) {
    if (!this.store[exchange]) {
      this.store[exchange] = {};
    }
    
    if (!this.store[exchange][symbol]) {
      // 아직 초기화 안 됨 - 무시 (Booting 단계에서 API로 채워질 예정)
      return;
    }
    
    const data = this.store[exchange][symbol];
    
    // 완성된 캔들을 배열 맨 앞에 추가 (최신순)
    const completedCandle = {
      candle_date_time_utc: candle.candle_date_time_utc,
      opening_price: candle.open,
      high_price: candle.high,
      low_price: candle.low,
      trade_price: candle.close,
      timestamp: candle.timestamp
    };
    
    data.candles.unshift(completedCandle);
    
    // MAX_CANDLES 초과 시 오래된 것 제거
    if (data.candles.length > MAX_CANDLES) {
      data.candles = data.candles.slice(0, MAX_CANDLES);
    }
    
    data.updatedAt = Date.now();
    
    // console.log('[DATA] [CandleManager] 캔들 완성: ' + symbol + ' @ ' + candle.close);
  },
  
  // 초기화 완료 여부 확인 (Streaming 모드 전환 조건)
  isInitialized(exchange, symbol) {
    const data = this.get(exchange, symbol);
    return data && data.candles && data.candles.length >= 50;  // 최소 50개 이상이면 초기화 완료
  }
};

//  기존 upbitCandleCache 대체 (호환성 유지용 래퍼)
const upbitCandleCache = {
  get(symbol) {
    return CandleManager.get('upbit', symbol);
  },
  set(symbol, data) {
    if (data && data.candles) {
      CandleManager.initialize('upbit', symbol, data.timeframe || 1, data.candles);
    }
  },
  has(symbol) {
    return CandleManager.hasData('upbit', symbol, momentumTimeframe);
  },
  get size() {
    return CandleManager.getSymbolCount('upbit');
  },
  forEach(callback) {
    const store = CandleManager.store.upbit || {};
    Object.keys(store).forEach(symbol => {
      callback(store[symbol], symbol);
    });
  }
};

const UPBIT_CANDLE_CACHE_FILE = path.join(DATA_DIR, 'upbit_candle_cache.json');  //  DATA_DIR 사용

// ---
// [문제 1 해결] coinData 스냅샷 파일 (서버 재시작 시 즉시 복원)
// ---
const COIN_DATA_SNAPSHOT_FILE = path.join(DATA_DIR, 'coin_data_snapshot.json');  //  DATA_DIR 사용
let lastSnapshotSaveTime = 0;
const SNAPSHOT_SAVE_INTERVAL = 10000; // 10초마다 저장

// ---
//  모멘텀 캐시 파일 (서버 재시작 시 즉시 복원)
// ---
const MOMENTUM_CACHE_FILE = path.join(DATA_DIR, 'momentum_cache.json');  //  DATA_DIR 사용
let lastMomentumCacheSaveTime = 0;
const MOMENTUM_CACHE_SAVE_INTERVAL = 30000; // 30초마다 저장

// ════════════════════════════════════════════════════════════════
//  다중 클라이언트 아키텍처
// - 전역 momentumTimeframe 제거! → 클라이언트별 독립 관리
// - 각 WebSocket 클라이언트가 자기 타임프레임을 독립적으로 선택
// - 서버는 모든 타임프레임 캐시를 유지하고 요청에 따라 해당 데이터 반환
// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════
//  서버 기본 타임프레임을 1분으로 변경 (프론트엔드와 일치!)
// - 기존: DEFAULT_TIMEFRAME = 240 (서버 4시간 ↔ UI 1분 불일치!)
// - 수정: DEFAULT_TIMEFRAME = 1 (서버와 UI 모두 1분)
// ════════════════════════════════════════════════════════════════
const DEFAULT_TIMEFRAME = 1;  //  프론트엔드와 일치시킴!
let serverDefaultTimeframe = DEFAULT_TIMEFRAME;  //  서버 기본값 (신규 접속자용)

//  클라이언트별 타임프레임 관리 (WebSocket 세션별)
// Key: WebSocket 객체, Value: 타임프레임 (1, 3, 5, 15, 30, 60, 240)
const clientTimeframes = new Map();

// ════════════════════════════════════════════════════════════════
//  타임프레임별 클라이언트 구독 관리
// - Key: Timeframe (number, 예: 1, 3, 5, 15, 30, 60, 240)
// - Value: Set<WebSocket>
// - 목적: broadcastCoinData에서 매번 그룹화하지 않고 직접 접근
// ════════════════════════════════════════════════════════════════
const subscriptions = new Map();

//  구독 관리 헬퍼 함수
// - 이전 타임프레임에서 제거하고 새 타임프레임에 등록
// - 연결/변경/해제 시 일관된 관리
function subscribeToTimeframe(ws, newTimeframe) {
  if (!ws) return;
  
  const oldTimeframe = ws.clientTimeframe;
  
  // 1. 이전 타임프레임에서 제거 (있다면)
  if (oldTimeframe !== undefined && oldTimeframe !== newTimeframe) {
    const oldSet = subscriptions.get(oldTimeframe);
    if (oldSet) {
      oldSet.delete(ws);
      // 빈 Set은 제거하지 않음 (재사용 위해)
    }
  }
  
  // 2. 새 타임프레임에 등록
  if (!subscriptions.has(newTimeframe)) {
    subscriptions.set(newTimeframe, new Set());
  }
  subscriptions.get(newTimeframe).add(ws);
  
  // 3. ws 객체에도 저장 (빠른 접근용)
  ws.clientTimeframe = newTimeframe;
  
  // 4. clientTimeframes Map에도 저장 (역방향 조회용, 하위 호환)
  clientTimeframes.set(ws, newTimeframe);
}

//  구독 해제 헬퍼 함수 (연결 종료 시)
function unsubscribeClient(ws) {
  if (!ws) return;
  
  const tf = ws.clientTimeframe;
  if (tf !== undefined) {
    const tfSet = subscriptions.get(tf);
    if (tfSet) {
      tfSet.delete(ws);
    }
  }
  
  clientTimeframes.delete(ws);
}

//  하위 호환성을 위한 getter (기존 코드에서 momentumTimeframe 참조 시)
// → 서버 기본 타임프레임 반환 (Phase 1 백필 등에서 사용)
let momentumTimeframe = DEFAULT_TIMEFRAME;

const ALLOWED_TIMEFRAMES = [1, 3, 5, 10, 15, 30, 60, 240];
const BITHUMB_DIRECT_TIMEFRAMES = [1, 3, 5, 10, 30, 60];

// ════════════════════════════════════════════════════════════════
//  JIT 백필 락(Lock) 시스템
// - 동일 타임프레임에 대해 중복 백필 방지
// - 1000명이 동시에 요청해도 실제 백필은 1번만!
// ════════════════════════════════════════════════════════════════
const jitBackfillInProgress = new Map();  // { 3: Promise, 5: Promise, ... }
const jitBackfillCompleted = new Set();   // 이미 백필 완료된 타임프레임
const jitBackfillFailCount = new Map();   //  백필 실패 횟수 { 3: 1, 5: 2, ... }
const MAX_BACKFILL_RETRY = 3;             //  최대 3회 재시도 후 강제 완료
const unavailableSymbolsPerTf = new Map(); //  백필 불가능한 심볼 {tf: Set{symbols}}

const BITHUMB_INTERVAL_MAP = {
  1: '1m', 3: '3m', 5: '5m', 10: '10m', 30: '30m', 60: '1h',
  360: '6h', 720: '12h', 1440: '24h'
};

//  업비트 타임프레임 매핑 (업비트는 모든 타임프레임 직접 지원)
const UPBIT_INTERVAL_MAP = {
  1: 1, 3: 3, 5: 5, 10: 10, 15: 15, 30: 30, 60: 60, 240: 240
};

//  빗썸 Multi-TF 직접 지원 타임프레임 (15분, 240분은 합성 필요)
const BITHUMB_MULTI_TF_DIRECT = [1, 3, 5, 30, 60];
const BITHUMB_MULTI_TF_SYNTHETIC = [15, 240];  // 합성 필요

function isValidTimeframe(unit) {
  const num = Number(unit);
  return Number.isInteger(num) && ALLOWED_TIMEFRAMES.includes(num);
}

// ---
// 다차원 모멘텀 캐시 초기화 (명세 2)
// ---
function initMomentumCacheMap() {
  ALLOWED_TIMEFRAMES.forEach(tf => {
    momentumCacheMap.upbit[tf] = new Map();
    momentumCacheMap.bithumb[tf] = new Map();
  });
  console.log('[CACHE] 다차원 모멘텀 캐시 초기화 완료 (타임프레임: ' + ALLOWED_TIMEFRAMES.join(', ') + '분)');
}

// ---
// 동적 마켓 코드 조회 (명세 1: 하드코딩 제거)
// ---
async function fetchMarketCodes() {
  console.log('[SCAN] 동적 마켓 코드 조회 시작...');
  
  // ---
  // 1. 업비트 마켓 조회 (KRW 마켓)
  // ---
  try {
    const upbitResponse = await axios.get('https://api.upbit.com/v1/market/all', {
      timeout: 10000,
      headers: { 'Accept': 'application/json' }
    });
    
    if (upbitResponse.data && Array.isArray(upbitResponse.data)) {
      // KRW 마켓만 필터링
      UPBIT_MARKETS = upbitResponse.data
        .filter(m => m.market && m.market.startsWith('KRW-'))
        .map(m => m.market.replace('KRW-', ''));
      console.log('[OK] 업비트 마켓 조회 완료: ' + UPBIT_MARKETS.length + '개 코인');
    }
  } catch (error) {
    console.error('[ERROR] 업비트 마켓 조회 실패:', error.message);
    // 실패 시 폴백: 기본 코인 리스트 사용
    UPBIT_MARKETS = getDefaultCoinList();
    console.log('[WARN] 업비트 폴백 마켓 사용: ' + UPBIT_MARKETS.length + '개 코인');
  }
  
  // ---
  // 2. 빗썸 마켓 조회 (KRW 마켓)
  // ---
  try {
    const bithumbResponse = await axios.get('https://api.bithumb.com/public/ticker/ALL_KRW', {
      timeout: 10000
    });
    
    if (bithumbResponse.data && bithumbResponse.data.status === '0000' && bithumbResponse.data.data) {
      // data 객체의 키들이 코인 심볼 (date 제외)
      BITHUMB_MARKETS = Object.keys(bithumbResponse.data.data)
        .filter(key => key !== 'date');
      console.log('[OK] 빗썸 마켓 조회 완료: ' + BITHUMB_MARKETS.length + '개 코인');
    }
  } catch (error) {
    console.error('[ERROR] 빗썸 마켓 조회 실패:', error.message);
    // 실패 시 폴백: 기본 코인 리스트 사용
    BITHUMB_MARKETS = getDefaultCoinList();
    console.log('[WARN] 빗썸 폴백 마켓 사용: ' + BITHUMB_MARKETS.length + '개 코인');
  }
  
  // ---
  // 3.  바이낸스 현물 마켓 조회 (USDT 페어)
  // - GET https://api.binance.com/api/v3/exchangeInfo
  // - quoteAsset === 'USDT' && status === 'TRADING' 필터링
  // ---
  try {
    console.log('[SCAN] 바이낸스 현물 마켓 조회 중...');
    const binanceSpotResponse = await axios.get('https://api.binance.com/api/v3/exchangeInfo', {
      timeout: 15000,
      headers: { 'Accept': 'application/json' }
    });
    
    if (binanceSpotResponse.data && binanceSpotResponse.data.symbols) {
      // USDT 페어 && TRADING 상태만 필터링
      //  심볼 정규화: 'BTCUSDT' → 'BTC' (기초 자산만 저장)
      BINANCE_SPOT_MARKETS = binanceSpotResponse.data.symbols
        .filter(s => s.quoteAsset === 'USDT' && s.status === 'TRADING')
        .map(s => s.symbol.replace(/USDT$/, ''));  // 'BTC', 'ETH' 형태
      console.log('[OK] 바이낸스 현물 마켓 조회 완료: ' + BINANCE_SPOT_MARKETS.length + '개 페어 (정규화됨)');
    }
  } catch (error) {
    console.error('[ERROR] 바이낸스 현물 마켓 조회 실패:', error.message);
    BINANCE_SPOT_MARKETS = [];
  }
  
  // ---
  // 4.  바이낸스 선물 마켓 조회 (USDT-M 무기한)
  // - GET https://fapi.binance.com/fapi/v1/exchangeInfo
  // - contractType === 'PERPETUAL' && quoteAsset === 'USDT' 필터링
  // ---
  try {
    console.log('[SCAN] 바이낸스 선물 마켓 조회 중...');
    const binanceFuturesResponse = await axios.get('https://fapi.binance.com/fapi/v1/exchangeInfo', {
      timeout: 15000,
      headers: { 'Accept': 'application/json' }
    });
    
    if (binanceFuturesResponse.data && binanceFuturesResponse.data.symbols) {
      // USDT-M 무기한 선물만 필터링
      //  심볼 정규화: 'BTCUSDT' → 'BTC' (기초 자산만 저장)
      BINANCE_FUTURES_MARKETS = binanceFuturesResponse.data.symbols
        .filter(s => s.contractType === 'PERPETUAL' && s.quoteAsset === 'USDT' && s.status === 'TRADING')
        .map(s => s.symbol.replace(/USDT$/, ''));  // 'BTC', 'ETH' 형태
      console.log('[OK] 바이낸스 선물 마켓 조회 완료: ' + BINANCE_FUTURES_MARKETS.length + '개 페어 (정규화됨)');
    }
  } catch (error) {
    console.error('[ERROR] 바이낸스 선물 마켓 조회 실패:', error.message);
    BINANCE_FUTURES_MARKETS = [];
  }
  
  // ---
  // 5.  OKX 현물 마켓 조회 (USDT 페어)
  // - GET https://www.okx.com/api/v5/public/instruments?instType=SPOT
  // - instId가 '-USDT'로 끝나는 것만 필터링
  // ---
  try {
    console.log('[SCAN] OKX 현물 마켓 조회 중...');
    const okxSpotResponse = await axios.get('https://www.okx.com/api/v5/public/instruments', {
      params: { instType: 'SPOT' },
      timeout: 15000,
      headers: { 'Accept': 'application/json' }
    });
    
    if (okxSpotResponse.data && okxSpotResponse.data.code === '0' && okxSpotResponse.data.data) {
      // USDT 페어만 필터링
      //  심볼 정규화: 'BTC-USDT' → 'BTC' (기초 자산만 저장)
      OKX_SPOT_MARKETS = okxSpotResponse.data.data
        .filter(s => s.instId && s.instId.endsWith('-USDT') && s.state === 'live')
        .map(s => s.instId.replace(/-USDT$/, ''));  // 'BTC', 'ETH' 형태
      console.log('[OK] OKX 현물 마켓 조회 완료: ' + OKX_SPOT_MARKETS.length + '개 페어 (정규화됨)');
    }
  } catch (error) {
    console.error('[ERROR] OKX 현물 마켓 조회 실패:', error.message);
    OKX_SPOT_MARKETS = [];
  }
  
  // ---
  // 6.  OKX 선물 마켓 조회 (USDT 무기한 스왑)
  // - GET https://www.okx.com/api/v5/public/instruments?instType=SWAP
  // - instId가 '-USDT-SWAP'으로 끝나는 것만 필터링
  // ---
  try {
    console.log('[SCAN] OKX 선물 마켓 조회 중...');
    const okxFuturesResponse = await axios.get('https://www.okx.com/api/v5/public/instruments', {
      params: { instType: 'SWAP' },
      timeout: 15000,
      headers: { 'Accept': 'application/json' }
    });
    
    if (okxFuturesResponse.data && okxFuturesResponse.data.code === '0' && okxFuturesResponse.data.data) {
      // USDT 무기한 스왑만 필터링
      //  심볼 정규화: 'BTC-USDT-SWAP' → 'BTC' (기초 자산만 저장)
      OKX_FUTURES_MARKETS = okxFuturesResponse.data.data
        .filter(s => s.instId && s.instId.endsWith('-USDT-SWAP') && s.state === 'live')
        .map(s => s.instId.replace(/-USDT-SWAP$/, ''));  // 'BTC', 'ETH' 형태
      console.log('[OK] OKX 선물 마켓 조회 완료: ' + OKX_FUTURES_MARKETS.length + '개 페어 (정규화됨)');
    }
  } catch (error) {
    console.error('[ERROR] OKX 선물 마켓 조회 실패:', error.message);
    OKX_FUTURES_MARKETS = [];
  }
  
  marketsLoaded = true;
  
  // 전체 마켓 수 요약 로그
  console.log('[DONE] 동적 마켓 코드 조회 완료!');
  console.log('   ├─ 업비트: ' + UPBIT_MARKETS.length + '개');
  console.log('   ├─ 빗썸: ' + BITHUMB_MARKETS.length + '개');
  console.log('   ├─ 바이낸스 현물: ' + BINANCE_SPOT_MARKETS.length + '개');
  console.log('   ├─ 바이낸스 선물: ' + BINANCE_FUTURES_MARKETS.length + '개');
  console.log('   ├─ OKX 현물: ' + OKX_SPOT_MARKETS.length + '개');
  console.log('   └─ OKX 선물: ' + OKX_FUTURES_MARKETS.length + '개');
  console.log('   [DATA] 총 ' + (UPBIT_MARKETS.length + BITHUMB_MARKETS.length + BINANCE_SPOT_MARKETS.length + BINANCE_FUTURES_MARKETS.length + OKX_SPOT_MARKETS.length + OKX_FUTURES_MARKETS.length) + '개 마켓');
}

// 폴백용 기본 코인 리스트
function getDefaultCoinList() {
  return [
    'BTC', 'ETH', 'XRP', 'SOL', 'ADA', 'DOT', 'LINK', 'AVAX', 'DOGE', 'MATIC',
    'UNI', 'ATOM', 'NEAR', 'APT', 'ARB', 'OP', 'IMX', 'SAND', 'MANA', 'AXS',
    'GALA', 'CHZ', 'ENJ', 'FLOW', 'ICP', 'FTM', 'ALGO', 'VET', 'XTZ', 'EOS',
    'HBAR', 'QNT', 'GRT', 'LDO', 'CRV', 'MKR', 'AAVE', 'SNX', 'COMP', 'SUSHI',
    '1INCH', 'BAT', 'ZRX', 'ANKR', 'CVC', 'STORJ', 'THETA', 'ENS', 'STX', 'SXP',
    'KAVA', 'AERGO', 'CELR', 'CTC', 'QTUM', 'BTG', 'STRAX', 'WAXP', 'POWR', 'MLK'
  ];
}

// ---
//  GlobalApiScheduler - 글로벌 거래소 API Rate Limit 관리
// - 바이낸스: 1200 requests/min (20/sec)
// - OKX: 20 requests/2 sec (10/sec)
// - 안전하게 50ms 간격으로 요청 (초당 20개)
// ---
const GlobalApiScheduler = {
  queue: [],
  isProcessing: false,
  requestDelay: 200,  //  50ms → 200ms (더 안전하게)
  
  // 요청 추가
  async request(url, options = {}) {
    return new Promise((resolve, reject) => {
      this.queue.push({ url, options, resolve, reject });
      this.processQueue();
    });
  },
  
  // 큐 처리
  async processQueue() {
    if (this.isProcessing || this.queue.length === 0) return;
    
    this.isProcessing = true;
    
    while (this.queue.length > 0) {
      const { url, options, resolve, reject } = this.queue.shift();
      
      try {
        const response = await axios.get(url, {
          timeout: 10000,
          headers: { 'Accept': 'application/json' },
          ...options
        });
        resolve(response);
      } catch (error) {
        reject(error);
      }
      
      // 요청 간 지연
      if (this.queue.length > 0) {
        await new Promise(r => setTimeout(r, this.requestDelay));
      }
    }
    
    this.isProcessing = false;
  }
};

// ---
//  글로벌 거래소 과거 캔들 데이터 수집 (Backfill)
// - 서버 시작 시 호출되어 과거 200개 1분봉을 CandleManager에 적재
// - Rate Limit 고려하여 배치 처리
// ---

// 바이낸스 현물 캔들 수집
//  interval 파라미터 추가 - 다양한 타임프레임 직접 요청 가능
async function fetchBinanceSpotCandles(symbol, limit = INITIAL_BACKFILL_COUNT, timeframe = 1) {
  const url = 'https://api.binance.com/api/v3/klines';
  const interval = BINANCE_INTERVAL_MAP[timeframe] || '1m';
  
  //  방어 코드: 이미 USDT 접미사가 있으면 제거 (double-suffix 방지)
  let normalizedSymbol = symbol;
  if (symbol.endsWith('USDT')) {
    console.warn('[WARN]  binance_spot symbol already has USDT suffix:', symbol);
    normalizedSymbol = symbol.replace(/USDT$/, '');
  }
  
  //  GlobalApiScheduler를 통한 요청 (Rate Limit 준수)
  const response = await GlobalApiScheduler.request(url, {
    params: {
      symbol: normalizedSymbol + 'USDT',
      interval: interval,
      limit: limit
    }
  });
  
  if (response && response.data && Array.isArray(response.data)) {
    // 바이낸스 캔들 형식을 업비트 호환 형식으로 변환
    // [openTime, open, high, low, close, volume, closeTime, ...]
    const candles = response.data.map(c => ({
      candle_date_time_utc: new Date(c[0]).toISOString(),
      opening_price: parseFloat(c[1]),
      high_price: parseFloat(c[2]),
      low_price: parseFloat(c[3]),
      trade_price: parseFloat(c[4]),
      timestamp: c[0],
      timeframe: timeframe  //  타임프레임 정보 추가
    }));
    
    return candles;
  }
  return null;
}

// 바이낸스 선물 캔들 수집
//  interval 파라미터 추가
async function fetchBinanceFuturesCandles(symbol, limit = INITIAL_BACKFILL_COUNT, timeframe = 1) {
  const url = 'https://fapi.binance.com/fapi/v1/klines';
  const interval = BINANCE_INTERVAL_MAP[timeframe] || '1m';
  
  //  방어 코드: 이미 USDT 접미사가 있으면 제거 (double-suffix 방지)
  let normalizedSymbol = symbol;
  if (symbol.endsWith('USDT')) {
    console.warn('[WARN]  binance_futures symbol already has USDT suffix:', symbol);
    normalizedSymbol = symbol.replace(/USDT$/, '');
  }
  
  //  GlobalApiScheduler를 통한 요청 (Rate Limit 준수)
  const response = await GlobalApiScheduler.request(url, {
    params: {
      symbol: normalizedSymbol + 'USDT',
      interval: interval,
      limit: limit
    }
  });
  
  if (response && response.data && Array.isArray(response.data)) {
    const candles = response.data.map(c => ({
      candle_date_time_utc: new Date(c[0]).toISOString(),
      opening_price: parseFloat(c[1]),
      high_price: parseFloat(c[2]),
      low_price: parseFloat(c[3]),
      trade_price: parseFloat(c[4]),
      timestamp: c[0],
      timeframe: timeframe  //  타임프레임 정보 추가
    }));
    
    return candles;
  }
  return null;
}

// OKX 현물 캔들 수집 (최대 300개, 이어달리기 지원)
//  timeframe 파라미터 추가
async function fetchOkxSpotCandles(symbol, limit = 300, after = null, timeframe = 1) {
  const url = 'https://www.okx.com/api/v5/market/candles';
  const bar = OKX_INTERVAL_MAP[timeframe] || '1m';
  
  //  방어 코드: 이미 -USDT 접미사가 있으면 제거 (double-suffix 방지)
  let normalizedSymbol = symbol;
  if (symbol.endsWith('-USDT')) {
    console.warn('[WARN]  okx_spot symbol already has -USDT suffix:', symbol);
    normalizedSymbol = symbol.replace(/-USDT$/, '');
  }
  
  const params = {
    instId: normalizedSymbol + '-USDT',
    bar: bar,
    limit: Math.min(limit, 300)  // OKX 최대 300개
  };
  
  // 이어달리기: after 파라미터로 특정 시점 이전 데이터 요청
  if (after) {
    params.after = after;
  }
  
  //  GlobalApiScheduler를 통한 요청 (Rate Limit 준수)
  const response = await GlobalApiScheduler.request(url, { params });
  
  if (response && response.data && response.data.code === '0' && response.data.data) {
    // OKX 캔들 형식: [ts, open, high, low, close, vol, volCcy, volCcyQuote, confirm]
    const candles = response.data.data.map(c => ({
      candle_date_time_utc: new Date(parseInt(c[0])).toISOString(),
      opening_price: parseFloat(c[1]),
      high_price: parseFloat(c[2]),
      low_price: parseFloat(c[3]),
      trade_price: parseFloat(c[4]),
      timestamp: parseInt(c[0]),
      timeframe: timeframe  //  타임프레임 정보 추가
    }));
    
    return candles;
  }
  return null;
}

// OKX 선물 캔들 수집 (최대 300개, 이어달리기 지원)
//  timeframe 파라미터 추가
async function fetchOkxFuturesCandles(symbol, limit = 300, after = null, timeframe = 1) {
  const url = 'https://www.okx.com/api/v5/market/candles';
  const bar = OKX_INTERVAL_MAP[timeframe] || '1m';
  
  //  방어 코드: 이미 -USDT-SWAP 접미사가 있으면 제거 (double-suffix 방지)
  let normalizedSymbol = symbol;
  if (symbol.endsWith('-USDT-SWAP')) {
    console.warn('[WARN]  okx_futures symbol already has -USDT-SWAP suffix:', symbol);
    normalizedSymbol = symbol.replace(/-USDT-SWAP$/, '');
  } else if (symbol.endsWith('-USDT')) {
    // -USDT만 있는 경우도 방어 (부분 접미사)
    console.warn('[WARN]  okx_futures symbol has partial -USDT suffix:', symbol);
    normalizedSymbol = symbol.replace(/-USDT$/, '');
  }
  
  const params = {
    instId: normalizedSymbol + '-USDT-SWAP',
    bar: bar,
    limit: Math.min(limit, 300)  // OKX 최대 300개
  };
  
  // 이어달리기: after 파라미터로 특정 시점 이전 데이터 요청
  if (after) {
    params.after = after;
  }
  
  //  GlobalApiScheduler를 통한 요청 (Rate Limit 준수)
  const response = await GlobalApiScheduler.request(url, { params });
  
  if (response && response.data && response.data.code === '0' && response.data.data) {
    const candles = response.data.data.map(c => ({
      candle_date_time_utc: new Date(parseInt(c[0])).toISOString(),
      opening_price: parseFloat(c[1]),
      high_price: parseFloat(c[2]),
      low_price: parseFloat(c[3]),
      trade_price: parseFloat(c[4]),
      timestamp: parseInt(c[0]),
      timeframe: timeframe  //  타임프레임 정보 추가
    }));
    
    return candles;
  }
  return null;
}

// ---
//  글로벌 거래소 스마트 Backfill (병렬 처리 + 재시도)
// - Promise.all로 20개씩 동시 요청하여 부팅 속도 대폭 단축
// - 청크 간 100ms 딜레이로 Rate Limit 준수
// -  fetchWithRetry로 일시적 오류 시 자동 재시도
// - 바이낸스: 1000개 직접 요청 (API 최대 지원)
// - OKX: 300개씩 이어달리기하여 최대 900개 수집
// ---
async function backfillGlobalCandles() {
  if (!marketsLoaded) {
    console.log('⏳ [Backfill] 마켓 로딩 대기 중...');
    return { total: 0, success: 0 };
  }
  
  console.log('[IN]  글로벌 거래소 스마트 Backfill 시작 (부족한 심볼만!)');
  const startTime = Date.now();
  
  let totalSymbols = 0;
  let successCount = 0;
  let mergedCount = 0;
  let failedCount = 0;
  let skippedCount = 0;  //  스킵된 심볼 카운트
  
  // ────────────────────────────────────────
  //  부족한 심볼 필터링 헬퍼 함수
  // - CandleManager.store 기준으로 360개 미만인 심볼만 반환
  // - 이미 충분한 심볼은 스킵 (API 낭비 방지)
  // ────────────────────────────────────────
  const getSymbolsNeedingBackfill = (exchange, marketList) => {
    if (!marketList || marketList.length === 0) return [];
    
    const MIN_CANDLES = 360;  // 모멘텀 계산에 필요한 최소 캔들
    const needsBackfill = [];
    const sufficient = [];
    
    for (const symbol of marketList) {
      const existing = CandleManager.store[exchange]?.[symbol]?.candles || [];
      if (existing.length < MIN_CANDLES) {
        needsBackfill.push(symbol);
      } else {
        sufficient.push(symbol);
      }
    }
    
    if (sufficient.length > 0) {
      console.log('   [SKIP] ' + exchange + ': ' + sufficient.length + '개 심볼 이미 충분 (360개+)');
    }
    
    return needsBackfill;
  };
  
  // ────────────────────────────────────────
  // 헬퍼 함수: 단일 심볼 Backfill 처리
  //  multiTfStore에도 저장 (모멘텀 캐시에서 읽을 수 있도록!)
  // ────────────────────────────────────────
  const processSymbol = async (symbol, exchange, fetchFn, limit) => {
    const candles = await fetchFn(symbol, limit);
    if (candles && candles.length > 0) {
      const existing = CandleManager.store[exchange]?.[symbol]?.candles || [];
      if (existing.length > 0) {
        CandleManager.mergeCandles(exchange, symbol, candles);
      } else {
        CandleManager.initializeFromBackfill(exchange, symbol, candles);
      }
      
      //  Option A: multiTfStore 저장 제거
      // Phase 1 backfill에서 모든 타임프레임 처리하므로 여기서 중복 저장 불필요
      // Fallback 로직으로 1분봉 없어도 대응 가능
      
      return { success: true, merged: existing.length > 0 };
    }
    return { success: false, merged: false };
  };
  
  // OKX용: 이어달리기 Backfill
  //  processOkxSymbol - 이어달리기 간 딜레이 추가
  //  Option A: multiTfStore 저장은 Phase 1에서만 (중복 제거)
  const processOkxSymbol = async (symbol, exchange, fetchFn) => {
    let allCandles = [];
    let afterTs = null;
    
    for (let round = 0; round < 3; round++) {
      const candles = await fetchFn(symbol, 300, afterTs);
      if (!candles || candles.length === 0) break;
      
      allCandles = [...allCandles, ...candles];
      
      if (candles.length >= 300) {
        afterTs = candles[candles.length - 1].timestamp;
        //  이어달리기 간 딜레이 추가 (Rate Limit 준수)
        await sleep(OKX_CHUNK_DELAY);
      } else {
        break;
      }
    }
    
    if (allCandles.length > 0) {
      const existing = CandleManager.store[exchange]?.[symbol]?.candles || [];
      if (existing.length > 0) {
        CandleManager.mergeCandles(exchange, symbol, allCandles);
      } else {
        CandleManager.initializeFromBackfill(exchange, symbol, allCandles);
      }
      
      //  Option A: multiTfStore 저장 제거
      // Phase 1 backfill에서 모든 타임프레임 처리하므로 여기서 중복 저장 불필요
      
      return { success: true, merged: existing.length > 0 };
    }
    return { success: false, merged: false };
  };
  
  // ────────────────────────────────────────
  // 1. 바이낸스 현물 Backfill (Rate Limit 대응)
  //  부족한 심볼만 백필!
  // ────────────────────────────────────────
  const binanceSpotNeeded = getSymbolsNeedingBackfill('binance_spot', BINANCE_SPOT_MARKETS);
  skippedCount += BINANCE_SPOT_MARKETS.length - binanceSpotNeeded.length;
  
  if (binanceSpotNeeded.length > 0) {
    console.log('   [DATA] [1/4] 바이낸스 현물 Backfill 중... (' + binanceSpotNeeded.length + '/' + BINANCE_SPOT_MARKETS.length + '개 부족)');
    const binanceSpotChunks = chunkArray(binanceSpotNeeded, BINANCE_CHUNK_SIZE);
    let binanceSpotSuccess = 0;
    let binanceSpotMerged = 0;
    let binanceSpotFailed = 0;
    
    for (const chunk of binanceSpotChunks) {
      const results = await Promise.all(
        chunk.map(symbol => processSymbol(symbol, 'binance_spot', fetchBinanceSpotCandles, INITIAL_BACKFILL_COUNT))
      );
      
      results.forEach(r => {
        if (r.success) binanceSpotSuccess++;
        else binanceSpotFailed++;
        if (r.merged) binanceSpotMerged++;
      });
      
      totalSymbols += chunk.length;
      await sleep(BINANCE_CHUNK_DELAY);
    }
    
    successCount += binanceSpotSuccess;
    mergedCount += binanceSpotMerged;
    failedCount += binanceSpotFailed;
    console.log('   [OK] 바이낸스 현물 완료: ' + binanceSpotSuccess + '/' + binanceSpotNeeded.length + ' (병합: ' + binanceSpotMerged + ', 실패: ' + binanceSpotFailed + ')');
  } else {
    console.log('   [SKIP] [1/4] 바이낸스 현물: 모든 심볼 충분 (' + BINANCE_SPOT_MARKETS.length + '개)');
  }
  
  // ────────────────────────────────────────
  // 2. 바이낸스 선물 Backfill (Rate Limit 대응)
  //  부족한 심볼만 백필!
  // ────────────────────────────────────────
  const binanceFuturesNeeded = getSymbolsNeedingBackfill('binance_futures', BINANCE_FUTURES_MARKETS);
  skippedCount += BINANCE_FUTURES_MARKETS.length - binanceFuturesNeeded.length;
  
  if (binanceFuturesNeeded.length > 0) {
    console.log('   [DATA] [2/4] 바이낸스 선물 Backfill 중... (' + binanceFuturesNeeded.length + '/' + BINANCE_FUTURES_MARKETS.length + '개 부족)');
    const binanceFuturesChunks = chunkArray(binanceFuturesNeeded, BINANCE_CHUNK_SIZE);
    let binanceFuturesSuccess = 0;
    let binanceFuturesMerged = 0;
    let binanceFuturesFailed = 0;
    
    for (const chunk of binanceFuturesChunks) {
      const results = await Promise.all(
        chunk.map(symbol => processSymbol(symbol, 'binance_futures', fetchBinanceFuturesCandles, INITIAL_BACKFILL_COUNT))
      );
      
      results.forEach(r => {
        if (r.success) binanceFuturesSuccess++;
        else binanceFuturesFailed++;
        if (r.merged) binanceFuturesMerged++;
      });
      
      totalSymbols += chunk.length;
      await sleep(BINANCE_CHUNK_DELAY);
    }
    
    successCount += binanceFuturesSuccess;
    mergedCount += binanceFuturesMerged;
    failedCount += binanceFuturesFailed;
    console.log('   [OK] 바이낸스 선물 완료: ' + binanceFuturesSuccess + '/' + binanceFuturesNeeded.length + ' (병합: ' + binanceFuturesMerged + ', 실패: ' + binanceFuturesFailed + ')');
  } else {
    console.log('   [SKIP] [2/4] 바이낸스 선물: 모든 심볼 충분 (' + BINANCE_FUTURES_MARKETS.length + '개)');
  }
  
  // ────────────────────────────────────────
  // 3. OKX 현물 Backfill (Rate Limit 대응: 느리게 처리)
  //  부족한 심볼만 백필!
  // ────────────────────────────────────────
  const okxSpotNeeded = getSymbolsNeedingBackfill('okx_spot', OKX_SPOT_MARKETS);
  skippedCount += OKX_SPOT_MARKETS.length - okxSpotNeeded.length;
  
  if (okxSpotNeeded.length > 0) {
    console.log('   [DATA] [3/4] OKX 현물 Backfill 중... (' + okxSpotNeeded.length + '/' + OKX_SPOT_MARKETS.length + '개 부족, 300x3 이어달리기)');
    const okxSpotChunks = chunkArray(okxSpotNeeded, OKX_CHUNK_SIZE);
    let okxSpotSuccess = 0;
    let okxSpotMerged = 0;
    let okxSpotFailed = 0;
    
    for (const chunk of okxSpotChunks) {
      const results = await Promise.all(
        chunk.map(symbol => processOkxSymbol(symbol, 'okx_spot', fetchOkxSpotCandles))
      );
      
      results.forEach(r => {
        if (r.success) okxSpotSuccess++;
        else okxSpotFailed++;
        if (r.merged) okxSpotMerged++;
      });
      
      totalSymbols += chunk.length;
      await sleep(OKX_CHUNK_DELAY);  //  OKX용 딜레이
    }
    
    successCount += okxSpotSuccess;
    mergedCount += okxSpotMerged;
    failedCount += okxSpotFailed;
    console.log('   [OK] OKX 현물 완료: ' + okxSpotSuccess + '/' + okxSpotNeeded.length + ' (병합: ' + okxSpotMerged + ', 실패: ' + okxSpotFailed + ')');
  } else {
    console.log('   [SKIP] [3/4] OKX 현물: 모든 심볼 충분 (' + OKX_SPOT_MARKETS.length + '개)');
  }
  
  // ────────────────────────────────────────
  // 4. OKX 선물 Backfill (Rate Limit 대응: 느리게 처리)
  //  부족한 심볼만 백필!
  // ────────────────────────────────────────
  const okxFuturesNeeded = getSymbolsNeedingBackfill('okx_futures', OKX_FUTURES_MARKETS);
  skippedCount += OKX_FUTURES_MARKETS.length - okxFuturesNeeded.length;
  
  if (okxFuturesNeeded.length > 0) {
    console.log('   [DATA] [4/4] OKX 선물 Backfill 중... (' + okxFuturesNeeded.length + '/' + OKX_FUTURES_MARKETS.length + '개 부족, 300x3 이어달리기)');
    const okxFuturesChunks = chunkArray(okxFuturesNeeded, OKX_CHUNK_SIZE);
    let okxFuturesSuccess = 0;
    let okxFuturesMerged = 0;
    let okxFuturesFailed = 0;
    
    for (const chunk of okxFuturesChunks) {
      const results = await Promise.all(
        chunk.map(symbol => processOkxSymbol(symbol, 'okx_futures', fetchOkxFuturesCandles))
      );
      
      results.forEach(r => {
        if (r.success) okxFuturesSuccess++;
        else okxFuturesFailed++;
        if (r.merged) okxFuturesMerged++;
      });
      
      totalSymbols += chunk.length;
      await sleep(OKX_CHUNK_DELAY);  //  OKX용 딜레이
    }
    
    successCount += okxFuturesSuccess;
    mergedCount += okxFuturesMerged;
    failedCount += okxFuturesFailed;
    console.log('   [OK] OKX 선물 완료: ' + okxFuturesSuccess + '/' + okxFuturesNeeded.length + ' (병합: ' + okxFuturesMerged + ', 실패: ' + okxFuturesFailed + ')');
  } else {
    console.log('   [SKIP] [4/4] OKX 선물: 모든 심볼 충분 (' + OKX_FUTURES_MARKETS.length + '개)');
  }
  
  // ────────────────────────────────────────
  // 완료 로그
  // ────────────────────────────────────────
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  const totalMarkets = BINANCE_SPOT_MARKETS.length + BINANCE_FUTURES_MARKETS.length + OKX_SPOT_MARKETS.length + OKX_FUTURES_MARKETS.length;
  
  console.log('[OK]  글로벌 스마트 Backfill 완료!');
  console.log('   [DATA] 백필: ' + successCount + '개 심볼');
  console.log('   [SKIP] 스킵: ' + skippedCount + '개 심볼 (이미 충분)');
  console.log('   [SYNC] 병합: ' + mergedCount + '개 심볼');
  console.log('   [ERROR] 실패: ' + failedCount + '개 심볼');
  console.log('   [TIME] 소요: ' + elapsed + '초 (기존 대비 대폭 단축!)');
  
  //  Backfill 완료 후 파일 저장
  if (successCount > 0) {
    saveGlobalCandleStoreToFile();
  }
  
  return { total: totalMarkets, success: successCount, merged: mergedCount, failed: failedCount, skipped: skippedCount };
}

// ---
//  Smart Priority Backfill
// - 신선도 기반 우선순위 증분 수집
// - 적게 필요한 것부터 수집 → 빠르게 채워지는 효과
// - 하나 완료될 때마다 즉시 브로드캐스트 (실시간 체감)
// ---
async function smartPriorityBackfill() {
  if (!marketsLoaded) {
    console.log('[WAIT]  Smart Priority Backfill 대기 중 (마켓 로딩 필요)...');
    return { total: 0, fresh: 0, backfilled: 0 };
  }
  
  //  메모리 상태 로깅 헬퍼
  function logMemory(label) {
    const mem = process.memoryUsage();
    const heapUsedMB = (mem.heapUsed / 1024 / 1024).toFixed(1);
    const heapTotalMB = (mem.heapTotal / 1024 / 1024).toFixed(1);
    const rssMB = (mem.rss / 1024 / 1024).toFixed(1);
    console.log('   [MEM] ' + label + ': heap=' + heapUsedMB + '/' + heapTotalMB + 'MB, rss=' + rssMB + 'MB');
  }
  
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('[IN]  Smart Priority Backfill 시작!');
  console.log('   원칙 1: 신선한 캐시는 건드리지 않음');
  console.log('   원칙 2: 적게 필요한 것부터 수집 (1개 → 10개 → 100개 → 360개)');
  console.log('   원칙 3: 하나 완료될 때마다 즉시 브로드캐스트');
  console.log('    spread 제거 + 메모리 모니터링 활성화');
  console.log('═══════════════════════════════════════════════════════════════');
  logMemory('시작');
  
  const TIMEFRAMES_TO_BACKFILL = [1, 3, 5, 15, 30, 60, 240];
  const EXCHANGES_CONFIG = [
    { name: 'upbit', markets: UPBIT_MARKETS || [], fetcher: fetchUpbitCandlesForBackfill },
    { name: 'bithumb', markets: BITHUMB_MARKETS || [], fetcher: fetchBithumbCandlesForBackfill },
    { name: 'binance_spot', markets: BINANCE_SPOT_MARKETS || [], fetcher: fetchBinanceSpotCandlesForBackfill },
    { name: 'binance_futures', markets: BINANCE_FUTURES_MARKETS || [], fetcher: fetchBinanceFuturesCandlesForBackfill },
    { name: 'okx_spot', markets: OKX_SPOT_MARKETS || [], fetcher: fetchOkxSpotCandlesForBackfill },
    { name: 'okx_futures', markets: OKX_FUTURES_MARKETS || [], fetcher: fetchOkxFuturesCandlesForBackfill }
  ];
  
  let totalProcessed = 0;
  let totalFresh = 0;
  let totalBackfilled = 0;
  
  // 타임프레임별로 처리 (현재 선택된 타임프레임 우선)
  let orderedTimeframes = [...TIMEFRAMES_TO_BACKFILL];
  const currentTf = momentumTimeframe;
  if (orderedTimeframes.includes(currentTf)) {
    orderedTimeframes = orderedTimeframes.filter(tf => tf !== currentTf);
    orderedTimeframes.unshift(currentTf);
  }
  
  for (const tf of orderedTimeframes) {
    console.log('');
    console.log('[TF]  ' + tf + '분봉 우선순위 백필 시작...');
    logMemory(tf + '분봉 시작');
    
    // 모든 거래소의 작업 목록 수집 (신선도 기반)
    const allTasks = [];
    
    for (const exchange of EXCHANGES_CONFIG) {
      if (exchange.markets.length === 0) continue;
      
      const analysis = CandleManager.analyzeCacheFreshness(exchange.name, exchange.markets, tf);
      
      totalFresh += analysis.fresh.length;
      
      // 노후 데이터 (증분 필요)
      for (const item of analysis.stale) {
        allTasks.push({
          exchange: exchange.name,
          symbol: item.symbol,
          timeframe: tf,
          neededCandles: item.neededCandles,
          fetcher: exchange.fetcher,
          type: 'STALE',
          stalenessSeconds: item.secondsBehind ?? Number.POSITIVE_INFINITY  //  추가
        });
      }
      
      // 캐시 없음 (전체 수집 필요)
      for (const item of analysis.missing) {
        allTasks.push({
          exchange: exchange.name,
          symbol: item.symbol,
          timeframe: tf,
          neededCandles: 363,  // 360 + 버퍼
          fetcher: exchange.fetcher,
          type: 'MISSING',
          stalenessSeconds: Number.POSITIVE_INFINITY  //  추가
        });
      }
    }
    
    //  증분 필요량 오름차순 + 신선도 순 정렬
    allTasks.sort((a, b) => {
      if (a.neededCandles !== b.neededCandles) {
        return a.neededCandles - b.neededCandles;
      }
      return (a.stalenessSeconds || Infinity) - (b.stalenessSeconds || Infinity);
    });
    
    if (allTasks.length === 0) {
      console.log('   [OK] ' + tf + '분봉: 모든 캐시 신선! (백필 불필요)');
      continue;
    }
    
    console.log('   [STAT] 백필 필요: ' + allTasks.length + '개 (적게 필요한 것부터 처리)');
    
    // ════════════════════════════════════════════════════════════════
    //  디버그: neededCandles 분포 확인 (증분수집 동작 검증)
    // ════════════════════════════════════════════════════════════════
    if (allTasks.length > 0) {
      // neededCandles별 개수 집계
      const distribution = {};
      for (let t = 0; t < allTasks.length; t++) {
        const nc = allTasks[t].neededCandles;
        const bucket = nc <= 10 ? '1-10' : nc <= 50 ? '11-50' : nc <= 100 ? '51-100' : nc <= 200 ? '101-200' : '201+';
        distribution[bucket] = (distribution[bucket] || 0) + 1;
      }
      console.log('   [DEBUG] neededCandles 분포:');
      console.log('      1-10개(증분): ' + (distribution['1-10'] || 0) + '개');
      console.log('      11-50개: ' + (distribution['11-50'] || 0) + '개');
      console.log('      51-100개: ' + (distribution['51-100'] || 0) + '개');
      console.log('      101-200개: ' + (distribution['101-200'] || 0) + '개');
      console.log('      201+개(전체수집): ' + (distribution['201+'] || 0) + '개');
      
      // 처음 5개 샘플 출력
      console.log('   [DEBUG] 샘플 (처음 5개):');
      for (let s = 0; s < Math.min(5, allTasks.length); s++) {
        const task = allTasks[s];
        console.log('      ' + task.exchange + '/' + task.symbol + ': needed=' + task.neededCandles + ', type=' + task.type);
      }
      
      // 201+ 개인 항목이 있으면 경고
      if (distribution['201+'] > 0) {
        console.log('   [WARN] 전체수집(201+) 항목 ' + distribution['201+'] + '개 발견! 캐시 문제 가능성');
        // 201+ 샘플 출력
        const fullFetchSamples = allTasks.filter(t => t.neededCandles > 200).slice(0, 3);
        for (let f = 0; f < fullFetchSamples.length; f++) {
          const task = fullFetchSamples[f];
          console.log('      [FULL] ' + task.exchange + '/' + task.symbol + ': needed=' + task.neededCandles + ', type=' + task.type);
        }
      }
    }
    
    // 청크 단위로 처리 (너무 많으면 Rate Limit)
    const CHUNK_SIZE = 10;  // 한 번에 10개씩
    let processedInTf = 0;
    
    for (let i = 0; i < allTasks.length; i += CHUNK_SIZE) {
      const chunk = allTasks.slice(i, i + CHUNK_SIZE);
      
      // 청크 내 작업 병렬 처리
      const chunkPromises = chunk.map(async (task) => {
        try {
          // 증분 수집 (필요한 만큼만!)
          const count = Math.min(task.neededCandles + 5, 200);  // 약간의 버퍼, 최대 200개
          
          // 해당 거래소의 fetcher 함수 호출
          if (task.fetcher) {
            await task.fetcher(task.symbol, count, task.timeframe);
          }
          
          return { success: true, task };
        } catch (err) {
          return { success: false, task, error: err.message };
        }
      });
      
      const results = await Promise.all(chunkPromises);
      const successCount = results.filter(r => r.success).length;
      processedInTf += successCount;
      totalBackfilled += successCount;
      totalProcessed += chunk.length;
      
      // ════════════════════════════════════════════════════════════════
      //  원복: 매 청크마다 브로드캐스트 (server206 원래 동작)
      // ════════════════════════════════════════════════════════════════
      if (successCount > 0) {
        try {
          updateGlobalMomentumCaches();
          applyGlobalMomentumToCoinData();
          broadcastToTimeframe(tf);  // 해당 타임프레임 클라이언트에게만
          
          const progress = Math.round((i + chunk.length) / allTasks.length * 100);
          console.log('   [LIVE] ' + tf + '분 청크 완료: +' + successCount + '개 (' + progress + '%)');
        } catch (broadcastErr) {
          console.error('   [WARN] 브로드캐스트 실패:', broadcastErr.message);
        }
      }
      
      //  원복: Rate Limit 방지 딜레이 100ms
      if (i + CHUNK_SIZE < allTasks.length) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
    
    console.log('   [OK] ' + tf + '분봉 완료: ' + processedInTf + '개 백필');
    logMemory(tf + '분봉 완료');
    
    // 타임프레임 완료 후 파일 저장
    saveMultiTfCandleStore();
  }
  
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('[OK]  Smart Priority Backfill 완료!');
  console.log('   총 처리: ' + totalProcessed + '개');
  console.log('   신선 유지: ' + totalFresh + '개 (백필 스킵)');
  console.log('   증분 수집: ' + totalBackfilled + '개');
  logMemory('전체 완료');
  console.log('═══════════════════════════════════════════════════════════════');
  
  return { total: totalProcessed, fresh: totalFresh, backfilled: totalBackfilled };
}

// ---
//  백필용 헬퍼 함수들 (증분 수집)
// ---
async function fetchUpbitCandlesForBackfill(symbol, count, timeframe) {
  try {
    const unit = UPBIT_INTERVAL_MAP[timeframe] || timeframe;
    const url = 'https://api.upbit.com/v1/candles/minutes/' + unit + '?market=KRW-' + symbol + '&count=' + count;
    const response = await UpbitApiScheduler.request(url);
    
    if (response.data && Array.isArray(response.data) && response.data.length > 0) {
      const candles = response.data.map(c => ({
        timestamp: new Date(c.candle_date_time_utc).getTime(),
        open: c.opening_price, high: c.high_price, low: c.low_price, close: c.trade_price,
        volume: c.candle_acc_trade_volume,
        high_price: c.high_price, low_price: c.low_price
      }));
      CandleManager.initializeMultiTfCandles('upbit', symbol, timeframe, candles);
      return candles.length;
    }
    return 0;
  } catch (err) {
    //  에러 로그 (Rate Limit 아니면 출력)
    if (err.message && !err.message.includes('429') && !err.message.includes('rate')) {
      console.error('   [ERR] upbit/' + symbol + '/' + timeframe + ': ' + err.message);
    }
    return 0;
  }
}

async function fetchBithumbCandlesForBackfill(symbol, count, timeframe) {
  try {
    const candles = await fetchBithumbCandlesMultiTf(symbol, count, timeframe);
    if (candles && candles.length > 0) {
      CandleManager.initializeMultiTfCandles('bithumb', symbol, timeframe, candles);
      return candles.length;
    }
    return 0;
  } catch (err) {
    if (err.message && !err.message.includes('429') && !err.message.includes('rate')) {
      console.error('   [ERR] bithumb/' + symbol + '/' + timeframe + ': ' + err.message);
    }
    return 0;
  }
}

async function fetchBinanceSpotCandlesForBackfill(symbol, count, timeframe) {
  try {
    //  버그 수정: fetchBinanceSpotCandles 내부에서 +USDT, interval 변환 처리
    // 인자 순서: (symbol, limit, timeframe) - symbol은 접미사 없이 전달
    const candles = await fetchBinanceSpotCandles(symbol, count, timeframe);
    if (candles && candles.length > 0) {
      CandleManager.initializeMultiTfCandles('binance_spot', symbol, timeframe, candles);
      return candles.length;
    }
    return 0;
  } catch (err) {
    if (err.message && !err.message.includes('429') && !err.message.includes('418') && !err.message.includes('rate')) {
      console.error('   [ERR] binance_spot/' + symbol + '/' + timeframe + ': ' + err.message);
    }
    return 0;
  }
}

async function fetchBinanceFuturesCandlesForBackfill(symbol, count, timeframe) {
  try {
    //  버그 수정: fetchBinanceFuturesCandles 내부에서 +USDT, interval 변환 처리
    // 인자 순서: (symbol, limit, timeframe) - symbol은 접미사 없이 전달
    const candles = await fetchBinanceFuturesCandles(symbol, count, timeframe);
    if (candles && candles.length > 0) {
      CandleManager.initializeMultiTfCandles('binance_futures', symbol, timeframe, candles);
      return candles.length;
    }
    return 0;
  } catch (err) {
    if (err.message && !err.message.includes('429') && !err.message.includes('418') && !err.message.includes('rate')) {
      console.error('   [ERR] binance_futures/' + symbol + '/' + timeframe + ': ' + err.message);
    }
    return 0;
  }
}

async function fetchOkxSpotCandlesForBackfill(symbol, count, timeframe) {
  try {
    //  버그 수정: fetchOkxSpotCandles 내부에서 +'-USDT', bar 변환 처리
    // 인자 순서: (symbol, limit, after, timeframe) - symbol은 접미사 없이, after=null
    const candles = await fetchOkxSpotCandles(symbol, count, null, timeframe);
    if (candles && candles.length > 0) {
      CandleManager.initializeMultiTfCandles('okx_spot', symbol, timeframe, candles);
      return candles.length;
    }
    return 0;
  } catch (err) {
    if (err.message && !err.message.includes('429') && !err.message.includes('rate')) {
      console.error('   [ERR] okx_spot/' + symbol + '/' + timeframe + ': ' + err.message);
    }
    return 0;
  }
}

async function fetchOkxFuturesCandlesForBackfill(symbol, count, timeframe) {
  try {
    //  버그 수정: fetchOkxFuturesCandles 내부에서 +'-USDT-SWAP', bar 변환 처리
    // 인자 순서: (symbol, limit, after, timeframe) - symbol은 접미사 없이, after=null
    const candles = await fetchOkxFuturesCandles(symbol, count, null, timeframe);
    if (candles && candles.length > 0) {
      CandleManager.initializeMultiTfCandles('okx_futures', symbol, timeframe, candles);
      return candles.length;
    }
    return 0;
  } catch (err) {
    if (err.message && !err.message.includes('429') && !err.message.includes('rate')) {
      console.error('   [ERR] okx_futures/' + symbol + '/' + timeframe + ': ' + err.message);
    }
    return 0;
  }
}

// ---
//  Multi-Timeframe Direct Backfill
// - 각 타임프레임별로 360개 캔들을 직접 API에서 수집
// - 1분봉 합성이 아닌 실제 해당 타임프레임 캔들 사용
// - n=359 보장하여 정확한 모멘텀 계산 가능
// ---
async function backfillMultiTimeframeCandles() {
  if (!marketsLoaded) {
    console.log('⏳  Multi-TF Backfill 대기 중 (마켓 로딩 필요)...');
    return { total: 0, success: 0 };
  }
  
  // ════════════════════════════════════════════════════════════════
  //  사용자 선택 타임프레임 우선 처리 (On-Demand Priority)
  // - 현재 사용자가 보고 있는 타임프레임을 배열 맨 앞으로 이동
  // - 4시간봉 보고 있으면 4시간봉부터, 1분봉 보고 있으면 1분봉부터 수집
  // ════════════════════════════════════════════════════════════════
  let targetTimeframes = [...MULTI_TF_BACKFILL_TIMEFRAMES];
  const currentTf = momentumTimeframe;  // 현재 사용자가 선택한 타임프레임
  
  // 현재 타임프레임을 배열 맨 앞으로 이동 (새치기)
  if (targetTimeframes.includes(currentTf)) {
    targetTimeframes = targetTimeframes.filter(tf => tf !== currentTf);
    targetTimeframes.unshift(currentTf);
  }
  
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('[IN]  Multi-Timeframe Direct Backfill (6개 거래소 완전 병렬화)');
  console.log('   현재 선택: ' + currentTf + '분봉 (최우선 수집)');
  console.log('   수집 순서: ' + targetTimeframes.join(' → ') + '분');
  console.log('   목표: 각 타임프레임별 ' + MIN_CANDLES_FOR_MOMENTUM + '개 캔들');
  console.log('   증분 수집: 기존 데이터 있으면 최신 ' + MULTI_TF_INCREMENTAL_COUNT + '개만 요청');
  console.log('═══════════════════════════════════════════════════════════════');
  
  const startTime = Date.now();
  let totalRequests = 0;
  let successCount = 0;
  let incrementalCount = 0;  // 증분 수집 카운트
  let fullCount = 0;         // 전체 수집 카운트
  
  // - 순차 실행 시 6분+ 소요 → 병렬 실행으로 2~3분대로 단축
  // - finally 블록으로 에러 시에도 backfilled 플래그 설정 보장
  // ════════════════════════════════════════════════════════════════
  
  // ════════════════════════════════════════════════════════════════
  //  업비트 Backfill 함수 (청크 단위 병렬 큐잉)
  //  timeframesToProcess 인자 추가 (Phase 1/2 분리용)
  // - 모든 심볼을 동시 큐잉하면 스케줄러 폭주 위험
  // - 20개씩 청크로 나눠서 Promise.all 처리 → 안정적인 속도 유지
  // - MIN_INTERVAL 150ms + 청크 처리 = 429 에러 방지
  // ════════════════════════════════════════════════════════════════
  const UPBIT_CHUNK_SIZE = 20;  //  동시 큐잉 수 제한
  
  const backfillUpbit = async (timeframesToProcess) => {
    const result = { total: 0, success: 0, full: 0, incremental: 0, logs: [] };
    
    for (const timeframe of timeframesToProcess) {
      let tfFull = 0, tfIncr = 0, tfFail = 0;
      
      //  20개씩 청크로 분할하여 처리
      const chunks = chunkArray(UPBIT_MARKETS, UPBIT_CHUNK_SIZE);
      
      for (const chunk of chunks) {
        const promises = chunk.map(async (symbol) => {
          const symbolResult = { full: 0, incr: 0, fail: 0 };
          
          try {
            const existingCount = CandleManager.getMultiTfCandleCount('upbit', symbol, timeframe);
            const isIncremental = existingCount >= MIN_CANDLES_FOR_MOMENTUM;
            
            if (isIncremental) {
              // 증분 수집: 최신 20개만
              const unit = UPBIT_INTERVAL_MAP[timeframe] || timeframe;
              const url = 'https://api.upbit.com/v1/candles/minutes/' + unit + '?market=KRW-' + symbol + '&count=' + MULTI_TF_INCREMENTAL_COUNT;
              const response = await UpbitApiScheduler.request(url);
              
              if (response.data && Array.isArray(response.data) && response.data.length > 0) {
                const candles = response.data.map(c => ({
                  timestamp: new Date(c.candle_date_time_utc).getTime(),
                  open: c.opening_price, high: c.high_price, low: c.low_price, close: c.trade_price,
                  volume: c.candle_acc_trade_volume,
                  high_price: c.high_price, low_price: c.low_price
                }));
                CandleManager.initializeMultiTfCandles('upbit', symbol, timeframe, candles);
                symbolResult.incr = 1;
              } else {
                symbolResult.fail = 1;
              }
            } else {
              // 전체 수집: fetchUpbitCandlesMultiTf 사용
              const candles = await fetchUpbitCandlesMultiTf(symbol, MIN_CANDLES_FOR_MOMENTUM + 10, timeframe);
              if (candles && candles.length > 0) {
                CandleManager.initializeMultiTfCandles('upbit', symbol, timeframe, candles);
                symbolResult.full = 1;
              } else {
                symbolResult.fail = 1;
              }
            }
            
          } catch (err) {
            symbolResult.fail = 1;
          } finally {
            //  성공하든 실패하든 수집 시도는 끝난 것이므로 플래그 설정
            CandleManager.setBackfilled('upbit', symbol, timeframe, true);
          }
          
          return symbolResult;
        });
        
        // 청크 내 모든 요청 완료 대기
        const chunkResults = await Promise.all(promises);
        
        // 결과 합산
        chunkResults.forEach(r => {
          tfFull += r.full;
          tfIncr += r.incr;
          tfFail += r.fail;
        });
      }
      
      result.full += tfFull;
      result.incremental += tfIncr;
      result.total += UPBIT_MARKETS.length;
      result.success += tfFull + tfIncr;
      result.logs.push('   [업비트] ' + timeframe + '분봉: 전체=' + tfFull + ', 증분=' + tfIncr + ', 실패=' + tfFail);
      
      // ════════════════════════════════════════════════════════════════
      //  이 타임프레임 완료! 즉시 캐시 갱신 + 해당 TF 클라이언트에게 브로드캐스트
      // - 다른 타임프레임 완료 안 기다리고 바로 전송!
      // - 동시접속 1000명 환경에서도 각 클라이언트가 자기 TF 데이터 즉시 받음
      // ════════════════════════════════════════════════════════════════
      try {
        updateGlobalMomentumCaches();
        applyGlobalMomentumToCoinData();
        broadcastToTimeframe(timeframe);
        console.log('[DONE]  업비트 ' + timeframe + '분봉 완료 → TF=' + timeframe + '분 클라이언트에게 즉시 브로드캐스트!');
      } catch (bcErr) {
        console.error('[DONE]  업비트 ' + timeframe + '분 브로드캐스트 오류:', bcErr.message);
      }
    }
    
    return result;
  };
  
  // ════════════════════════════════════════════════════════════════
  //  빗썸 Backfill 함수 (청크 단위 병렬 큐잉)
  // - 빗썸은 전용 스케줄러가 없으므로 완전 병렬화 시 Rate Limit 위험
  // - 20개씩 청크로 묶어서 병렬 처리 (업비트와 동일)
  // ════════════════════════════════════════════════════════════════
  const BITHUMB_CHUNK_SIZE = 20;  //  동시 요청 수 = 업비트와 동일
  
  //  timeframesToProcess 인자 추가 (Phase 1/2 분리용)
  const backfillBithumb = async (timeframesToProcess) => {
    const result = { total: 0, success: 0, full: 0, incremental: 0, logs: [] };
    
    for (const timeframe of timeframesToProcess) {
      let tfFull = 0, tfIncr = 0, tfFail = 0;
      
      //  20개씩 청크로 분할하여 처리
      const chunks = chunkArray(BITHUMB_MARKETS, BITHUMB_CHUNK_SIZE);
      
      for (const chunk of chunks) {
        const promises = chunk.map(async (symbol) => {
          const symbolResult = { full: 0, incr: 0, fail: 0 };
          
          try {
            const existingCount = CandleManager.getMultiTfCandleCount('bithumb', symbol, timeframe);
            const isIncremental = existingCount >= MIN_CANDLES_FOR_MOMENTUM;
            
            if (isIncremental) {
              // 증분 수집: 최신 캔들만
              const candles = await fetchBithumbCandlesMultiTf(symbol, MULTI_TF_INCREMENTAL_COUNT, timeframe);
              if (candles && candles.length > 0) {
                CandleManager.initializeMultiTfCandles('bithumb', symbol, timeframe, candles);
                symbolResult.incr = 1;
              } else {
                symbolResult.fail = 1;
              }
            } else {
              // 전체 수집
              const candles = await fetchBithumbCandlesMultiTf(symbol, MIN_CANDLES_FOR_MOMENTUM + 10, timeframe);
              if (candles && candles.length > 0) {
                CandleManager.initializeMultiTfCandles('bithumb', symbol, timeframe, candles);
                symbolResult.full = 1;
              } else {
                symbolResult.fail = 1;
              }
            }
            
          } catch (err) {
            symbolResult.fail = 1;
          } finally {
            //  성공하든 실패하든 수집 시도는 끝난 것이므로 플래그 설정
            CandleManager.setBackfilled('bithumb', symbol, timeframe, true);
          }
          
          return symbolResult;
        });
        
        // 청크 내 모든 요청 완료 대기
        const chunkResults = await Promise.all(promises);
        
        // 결과 합산
        chunkResults.forEach(r => {
          tfFull += r.full;
          tfIncr += r.incr;
          tfFail += r.fail;
        });
        
        // 청크 간 Rate Limit 대응 딜레이
        await sleep(200);
      }
      
      result.full += tfFull;
      result.incremental += tfIncr;
      result.total += BITHUMB_MARKETS.length;
      result.success += tfFull + tfIncr;
      result.logs.push('   [빗썸] ' + timeframe + '분봉: 전체=' + tfFull + ', 증분=' + tfIncr + ', 실패=' + tfFail);
      
      //  이 타임프레임 완료! 즉시 브로드캐스트
      try {
        updateGlobalMomentumCaches();
        applyGlobalMomentumToCoinData();
        broadcastToTimeframe(timeframe);
        console.log('[DONE]  빗썸 ' + timeframe + '분봉 완료 → TF=' + timeframe + '분 클라이언트에게 즉시 브로드캐스트!');
      } catch (bcErr) {
        console.error('[DONE]  빗썸 ' + timeframe + '분 브로드캐스트 오류:', bcErr.message);
      }
    }
    
    return result;
  };
  
  // ════════════════════════════════════════════════════════════════
  //  업비트+빗썸 개별 실행 제거 → 아래 전체 병렬 실행으로 통합
  // ════════════════════════════════════════════════════════════════
  

  // ────────────────────────────────────────
  // 헬퍼 함수: 바이낸스용 증분/전체 수집 처리
  //  finally 블록으로 무조건 backfilled 설정 (무한 Calc... 방지)
  // ────────────────────────────────────────
  const processBinanceSymbol = async (symbol, exchange, fetchFn, timeframe) => {
    let result = { success: false, incremental: false };
    
    try {
      const existingCount = CandleManager.getMultiTfCandleCount(exchange, symbol, timeframe);
      
      // 이미 충분한 캔들이 있으면 → 증분 수집 (최신 20개만)
      // 부족하면 → 전체 수집 (370개)
      const isIncremental = existingCount >= MIN_CANDLES_FOR_MOMENTUM;
      const limit = isIncremental ? MULTI_TF_INCREMENTAL_COUNT : (MIN_CANDLES_FOR_MOMENTUM + 10);
      
      const candles = await fetchFn(symbol, limit, timeframe);
      if (candles && candles.length > 0) {
        CandleManager.initializeMultiTfCandles(exchange, symbol, timeframe, candles);
        result = { success: true, incremental: isIncremental };
      }
    } finally {
      //  성공/실패 관계없이 무조건 backfilled 설정
      // → 데이터 없는 코인도 "Calc..." 대신 "-"로 표시됨
      CandleManager.setBackfilled(exchange, symbol, timeframe, true);
    }
    
    return result;
  };
  
  // ────────────────────────────────────────
  // 헬퍼 함수: OKX용 증분/전체 수집 처리 (이어달리기)
  //  이어달리기 간 딜레이 추가
  //  finally 블록으로 무조건 backfilled 설정 (무한 Calc... 방지)
  // ────────────────────────────────────────
  const processOkxSymbol = async (symbol, exchange, fetchFn, timeframe) => {
    let result = { success: false, incremental: false };
    
    try {
      const existingCount = CandleManager.getMultiTfCandleCount(exchange, symbol, timeframe);
      const isIncremental = existingCount >= MIN_CANDLES_FOR_MOMENTUM;
      
      if (isIncremental) {
        // 증분 수집: 최신 20개만
        const candles = await fetchFn(symbol, MULTI_TF_INCREMENTAL_COUNT, null, timeframe);
        if (candles && candles.length > 0) {
          CandleManager.initializeMultiTfCandles(exchange, symbol, timeframe, candles);
          result = { success: true, incremental: true };
        }
      } else {
        // 전체 수집: 이어달리기로 최대 600개
        let allCandles = [];
        let afterTs = null;
        
        for (let round = 0; round < 2; round++) {
          const candles = await fetchFn(symbol, 300, afterTs, timeframe);
          if (!candles || candles.length === 0) break;
          
          allCandles = [...allCandles, ...candles];
          
          if (candles.length >= 300) {
            afterTs = candles[candles.length - 1].timestamp;
            //  이어달리기 간 딜레이 추가 (Rate Limit 준수)
            await sleep(OKX_CHUNK_DELAY);
          } else {
            break;
          }
        }
        
        if (allCandles.length > 0) {
          CandleManager.initializeMultiTfCandles(exchange, symbol, timeframe, allCandles);
          result = { success: true, incremental: false };
        }
      }
    } finally {
      //  성공/실패 관계없이 무조건 backfilled 설정
      // → 데이터 없는 코인도 "Calc..." 대신 "-"로 표시됨
      CandleManager.setBackfilled(exchange, symbol, timeframe, true);
    }
    
    return result;
  };
  
  // ────────────────────────────────────────
  // 1/4: 바이낸스 현물 (Rate Limit 대응)

  // ════════════════════════════════════════════════════════════════
  //  바이낸스 현물 Backfill 함수
  //  timeframesToProcess 인자 추가 (Phase 1/2 분리용)
  // ════════════════════════════════════════════════════════════════
  const backfillBinanceSpot = async (timeframesToProcess) => {
    const result = { total: 0, success: 0, full: 0, incremental: 0, logs: [] };
    result.logs.push('[>] [바이낸스 현물] Multi-TF Backfill 시작...');
    
    for (const timeframe of timeframesToProcess) {
      let tfFull = 0, tfIncr = 0, tfFail = 0;
      
      const chunks = chunkArray([...BINANCE_SPOT_MARKETS], BINANCE_CHUNK_SIZE);
      for (const chunk of chunks) {
        const results = await Promise.all(
          chunk.map(symbol => processBinanceSymbol(symbol, 'binance_spot', fetchBinanceSpotCandles, timeframe))
        );
        
        results.forEach(r => {
          result.total++;
          if (r.success) {
            result.success++;
            if (r.incremental) { tfIncr++; result.incremental++; }
            else { tfFull++; result.full++; }
          } else {
            tfFail++;
          }
        });
        
        await sleep(BINANCE_CHUNK_DELAY);
      }
      
      result.logs.push('   [바이낸스 현물] ' + timeframe + '분봉: 전체=' + tfFull + ', 증분=' + tfIncr + ', 실패=' + tfFail);
      
      //  이 타임프레임 완료! 즉시 브로드캐스트
      try {
        updateGlobalMomentumCaches();
        applyGlobalMomentumToCoinData();
        broadcastToTimeframe(timeframe);
        console.log('[DONE]  바이낸스현물 ' + timeframe + '분봉 완료 → TF=' + timeframe + '분 클라이언트에게 즉시 브로드캐스트!');
      } catch (bcErr) {
        console.error('[DONE]  바이낸스현물 ' + timeframe + '분 브로드캐스트 오류:', bcErr.message);
      }
    }
    
    return result;
  };
  
  // ════════════════════════════════════════════════════════════════
  //  바이낸스 선물 Backfill 함수
  // ════════════════════════════════════════════════════════════════
  //  timeframesToProcess 인자 추가 (Phase 1/2 분리용)
  const backfillBinanceFutures = async (timeframesToProcess) => {
    const result = { total: 0, success: 0, full: 0, incremental: 0, logs: [] };
    result.logs.push('[>] [바이낸스 선물] Multi-TF Backfill 시작...');
    
    for (const timeframe of timeframesToProcess) {
      let tfFull = 0, tfIncr = 0, tfFail = 0;
      
      const chunks = chunkArray([...BINANCE_FUTURES_MARKETS], BINANCE_CHUNK_SIZE);
      for (const chunk of chunks) {
        const results = await Promise.all(
          chunk.map(symbol => processBinanceSymbol(symbol, 'binance_futures', fetchBinanceFuturesCandles, timeframe))
        );
        
        results.forEach(r => {
          result.total++;
          if (r.success) {
            result.success++;
            if (r.incremental) { tfIncr++; result.incremental++; }
            else { tfFull++; result.full++; }
          } else {
            tfFail++;
          }
        });
        
        await sleep(BINANCE_CHUNK_DELAY);
      }
      
      result.logs.push('   [바이낸스 선물] ' + timeframe + '분봉: 전체=' + tfFull + ', 증분=' + tfIncr + ', 실패=' + tfFail);
      
      //  이 타임프레임 완료! 즉시 브로드캐스트
      try {
        updateGlobalMomentumCaches();
        applyGlobalMomentumToCoinData();
        broadcastToTimeframe(timeframe);
        console.log('[DONE]  바이낸스선물 ' + timeframe + '분봉 완료 → TF=' + timeframe + '분 클라이언트에게 즉시 브로드캐스트!');
      } catch (bcErr) {
        console.error('[DONE]  바이낸스선물 ' + timeframe + '분 브로드캐스트 오류:', bcErr.message);
      }
    }
    
    return result;
  };
  
  // ════════════════════════════════════════════════════════════════
  //  OKX 현물 Backfill 함수
  //  timeframesToProcess 인자 추가 (Phase 1/2 분리용)
  // ════════════════════════════════════════════════════════════════
  const backfillOkxSpot = async (timeframesToProcess) => {
    const result = { total: 0, success: 0, full: 0, incremental: 0, logs: [] };
    result.logs.push('[>] [OKX 현물] Multi-TF Backfill 시작...');
    
    for (const timeframe of timeframesToProcess) {
      let tfFull = 0, tfIncr = 0, tfFail = 0;
      
      const chunks = chunkArray([...OKX_SPOT_MARKETS], OKX_CHUNK_SIZE);
      for (const chunk of chunks) {
        const results = await Promise.all(
          chunk.map(symbol => processOkxSymbol(symbol, 'okx_spot', fetchOkxSpotCandles, timeframe))
        );
        
        results.forEach(r => {
          result.total++;
          if (r.success) {
            result.success++;
            if (r.incremental) { tfIncr++; result.incremental++; }
            else { tfFull++; result.full++; }
          } else {
            tfFail++;
          }
        });
        
        await sleep(OKX_CHUNK_DELAY);
      }
      
      result.logs.push('   [OKX 현물] ' + timeframe + '분봉: 전체=' + tfFull + ', 증분=' + tfIncr + ', 실패=' + tfFail);
      
      //  이 타임프레임 완료! 즉시 브로드캐스트
      try {
        updateGlobalMomentumCaches();
        applyGlobalMomentumToCoinData();
        broadcastToTimeframe(timeframe);
        console.log('[DONE]  OKX현물 ' + timeframe + '분봉 완료 → TF=' + timeframe + '분 클라이언트에게 즉시 브로드캐스트!');
      } catch (bcErr) {
        console.error('[DONE]  OKX현물 ' + timeframe + '분 브로드캐스트 오류:', bcErr.message);
      }
    }
    
    return result;
  };
  
  // ════════════════════════════════════════════════════════════════
  //  OKX 선물 Backfill 함수
  // ════════════════════════════════════════════════════════════════
  //  timeframesToProcess 인자 추가 (Phase 1/2 분리용)
  const backfillOkxFutures = async (timeframesToProcess) => {
    const result = { total: 0, success: 0, full: 0, incremental: 0, logs: [] };
    result.logs.push('[>] [OKX 선물] Multi-TF Backfill 시작...');
    
    for (const timeframe of timeframesToProcess) {
      let tfFull = 0, tfIncr = 0, tfFail = 0;
      
      const chunks = chunkArray([...OKX_FUTURES_MARKETS], OKX_CHUNK_SIZE);
      for (const chunk of chunks) {
        const results = await Promise.all(
          chunk.map(symbol => processOkxSymbol(symbol, 'okx_futures', fetchOkxFuturesCandles, timeframe))
        );
        
        results.forEach(r => {
          result.total++;
          if (r.success) {
            result.success++;
            if (r.incremental) { tfIncr++; result.incremental++; }
            else { tfFull++; result.full++; }
          } else {
            tfFail++;
          }
        });
        
        await sleep(OKX_CHUNK_DELAY);
      }
      
      result.logs.push('   [OKX 선물] ' + timeframe + '분봉: 전체=' + tfFull + ', 증분=' + tfIncr + ', 실패=' + tfFail);
      
      //  이 타임프레임 완료! 즉시 브로드캐스트
      try {
        updateGlobalMomentumCaches();
        applyGlobalMomentumToCoinData();
        broadcastToTimeframe(timeframe);
        console.log('[DONE]  OKX선물 ' + timeframe + '분봉 완료 → TF=' + timeframe + '분 클라이언트에게 즉시 브로드캐스트!');
      } catch (bcErr) {
        console.error('[DONE]  OKX선물 ' + timeframe + '분 브로드캐스트 오류:', bcErr.message);
      }
    }
    
    return result;
  };
  
  // ════════════════════════════════════════════════════════════════
  //  Phase 1에서 모든 타임프레임 처리! (단일 클라이언트 가정 X)
  // ════════════════════════════════════════════════════════════════
  // 이전 문제: Phase 1에서 currentTf만 처리 → 다른 TF 클라이언트는 Phase 2까지 대기
  // 해결: 모든 타임프레임을 Phase 1에서 처리
  // 효과: 각 TF × 거래소 완료 시 해당 TF 클라이언트에게 즉시 브로드캐스트
  // ════════════════════════════════════════════════════════════════
  
  const phase1Timeframes = [...targetTimeframes];  //  모든 타임프레임!
  const phase2Timeframes = [];  //  Phase 2 제거!
  
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('[PHASE 1] 모든 타임프레임 수집 시작! (동시접속 1000명+ 대응)');
  console.log('   타임프레임: ' + phase1Timeframes.join(', ') + '분');
  console.log('   각 거래소 × 타임프레임 완료 시 해당 TF 클라이언트에게 즉시 브로드캐스트');
  console.log('   ⏱️ 업비트/빗썸: TF당 10~20초, OKX: TF당 수 분 (Rate Limit)');
  console.log('═══════════════════════════════════════════════════════════════');
  
  const phase1Start = Date.now();
  
  // ═══════════════════════════════════════════════════════════════
  // [PHASE 1] 현재 타임프레임 수집 - 개별 완료 즉시 브로드캐스트!
  //  Promise.all 대신 각 거래소별로 완료 시 즉시 처리
  // ═══════════════════════════════════════════════════════════════
  
  //  각 거래소 완료 시 즉시 캐시 업데이트 + 브로드캐스트하는 래퍼
  //  각 거래소 전체 완료 시 로그만 출력 (브로드캐스트는 backfill 함수 내부에서 처리)
  const broadcastOnComplete = (exchangeName) => {
    return () => {
      const elapsed = ((Date.now() - phase1Start) / 1000).toFixed(1);
      console.log('[OK]  ' + exchangeName + ' 모든 타임프레임 완료! (총 ' + elapsed + '초)');
      //  브로드캐스트는 backfill 함수 내부에서 각 타임프레임별로 처리됨
    };
  };
  
  // 각 거래소별 Promise 생성 (완료 시 즉시 브로드캐스트)
  const upbitPromise = backfillUpbit(phase1Timeframes).then(result => {
    broadcastOnComplete('업비트')();
    return result;
  });
  
  const bithumbPromise = backfillBithumb(phase1Timeframes).then(result => {
    broadcastOnComplete('빗썸')();
    return result;
  });
  
  const binanceSpotPromise = backfillBinanceSpot(phase1Timeframes).then(result => {
    broadcastOnComplete('바이낸스현물')();
    return result;
  });
  
  const binanceFuturesPromise = backfillBinanceFutures(phase1Timeframes).then(result => {
    broadcastOnComplete('바이낸스선물')();
    return result;
  });
  
  const okxSpotPromise = backfillOkxSpot(phase1Timeframes).then(result => {
    broadcastOnComplete('OKX현물')();
    return result;
  });
  
  const okxFuturesPromise = backfillOkxFutures(phase1Timeframes).then(result => {
    broadcastOnComplete('OKX선물')();
    return result;
  });
  
  // 모든 거래소 완료 대기 (개별 완료 시 이미 브로드캐스트됨)
  const [
    upbitResult1,
    bithumbResult1,
    binanceSpotResult1,
    binanceFuturesResult1,
    okxSpotResult1,
    okxFuturesResult1
  ] = await Promise.all([
    upbitPromise,
    bithumbPromise,
    binanceSpotPromise,
    binanceFuturesPromise,
    okxSpotPromise,
    okxFuturesPromise
  ]);
  
  // Phase 1 결과 합산
  const phase1Results = [upbitResult1, bithumbResult1, binanceSpotResult1, binanceFuturesResult1, okxSpotResult1, okxFuturesResult1];
  phase1Results.forEach(r => {
    totalRequests += r.total;
    successCount += r.success;
    fullCount += r.full;
    incrementalCount += r.incremental;
  });
  
  const phase1Elapsed = ((Date.now() - phase1Start) / 1000).toFixed(1);
  
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('[PHASE 1 완료!] ' + currentTf + '분봉 데이터 준비 완료');
  console.log('   ⏱️ 소요 시간: ' + phase1Elapsed + '초');
  console.log('   성공: ' + successCount + '/' + totalRequests);
  console.log('   📡 개별 완료 시 이미 브로드캐스트 완료됨 (server201)');
  console.log('═══════════════════════════════════════════════════════════════');
  
  // ═══════════════════════════════════════════════════════════════
  // [Phase 1 완료 후] 최종 UI 갱신 (누락 방지)
  //  개별 완료 시 이미 브로드캐스트했지만, 마지막으로 한 번 더
  // ═══════════════════════════════════════════════════════════════
  try {
    // 현재 타임프레임의 모멘텀 계산 및 캐시 갱신
    updateGlobalMomentumCaches();
    applyGlobalMomentumToCoinData();
    
    //  현재 타임프레임 클라이언트에게 전송
    broadcastToTimeframe(currentTf);
    
    //  중복 브로드캐스트 방지 플래그 설정
    if (typeof initialBroadcastDone !== 'undefined') {
      initialBroadcastDone[currentTf] = true;
    }
    
    console.log('[UI]  ' + currentTf + '분봉 → Phase 1 전체 완료 최종 브로드캐스트!');
  } catch (uiErr) {
    console.error('[UI] 갱신 중 오류:', uiErr.message);
  }
  
  // Multi-TF 캔들 저장 (Phase 1 데이터)
  saveMultiTfCandleStore();
  
  // ═══════════════════════════════════════════════════════════════
  // [PHASE 2] 나머지 타임프레임 백그라운드 수집 (Non-Blocking)
  // ═══════════════════════════════════════════════════════════════
  if (phase2Timeframes.length > 0) {
    console.log('');
    console.log('[PHASE 2] 나머지 ' + phase2Timeframes.length + '개 타임프레임 백그라운드 수집 시작...');
    console.log('   대상: ' + phase2Timeframes.join(', ') + '분');
    console.log('   💡 사용자는 이미 ' + currentTf + '분봉 데이터로 화면 이용 중');
    console.log('   🔄  각 타임프레임별 점진적 갱신 적용!');
    
    // Fire and Forget - await 하지 않음!
    (async () => {
      const phase2Start = Date.now();
      let p2Total = 0, p2Success = 0;
      
      try {
        // ════════════════════════════════════════════════════════════════
        //  점진적 갱신: 한 타임프레임씩 순차 처리
        // - 기존: Promise.all로 모든 TF 다 끝날 때까지 대기
        // - 수정: for 루프로 한 TF 끝날 때마다 즉시 캐시 갱신 + 브로드캐스트
        //  각 거래소 완료 시마다 즉시 브로드캐스트 (OKX 20분 대기 X)
        // ════════════════════════════════════════════════════════════════
        for (const tf of phase2Timeframes) {
          console.log('[PHASE 2] ' + tf + '분봉 수집 시작...');
          const tfStart = Date.now();
          
          //  각 거래소 완료 시 즉시 브로드캐스트하는 래퍼
          const broadcastOnCompleteTf = (exchangeName) => {
            return () => {
              const elapsed = ((Date.now() - tfStart) / 1000).toFixed(1);
              console.log('[DONE]  ' + tf + '분 ' + exchangeName + ' 완료! (' + elapsed + '초) → 즉시 브로드캐스트');
              
              try {
                updateGlobalMomentumCaches();
                applyGlobalMomentumToCoinData();
                broadcastToTimeframe(tf);
                
                if (typeof initialBroadcastDone !== 'undefined') {
                  initialBroadcastDone[tf] = true;
                }
              } catch (err) {
                console.error('[DONE]  ' + tf + '분 ' + exchangeName + ' 브로드캐스트 오류:', err.message);
              }
            };
          };
          
          // 각 거래소별 Promise 생성 (완료 시 즉시 브로드캐스트)
          const upbitP = backfillUpbit([tf]).then(r => { broadcastOnCompleteTf('업비트')(); return r; });
          const bithumbP = backfillBithumb([tf]).then(r => { broadcastOnCompleteTf('빗썸')(); return r; });
          const binanceSpotP = backfillBinanceSpot([tf]).then(r => { broadcastOnCompleteTf('바이낸스현물')(); return r; });
          const binanceFuturesP = backfillBinanceFutures([tf]).then(r => { broadcastOnCompleteTf('바이낸스선물')(); return r; });
          const okxSpotP = backfillOkxSpot([tf]).then(r => { broadcastOnCompleteTf('OKX현물')(); return r; });
          const okxFuturesP = backfillOkxFutures([tf]).then(r => { broadcastOnCompleteTf('OKX선물')(); return r; });
          
          const [
            upbitResult,
            bithumbResult,
            binanceSpotResult,
            binanceFuturesResult,
            okxSpotResult,
            okxFuturesResult
          ] = await Promise.all([
            upbitP,
            bithumbP,
            binanceSpotP,
            binanceFuturesP,
            okxSpotP,
            okxFuturesP
          ]);
          
          // 이 타임프레임 결과 집계
          const tfResults = [upbitResult, bithumbResult, binanceSpotResult, binanceFuturesResult, okxSpotResult, okxFuturesResult];
          let tfTotal = 0, tfSuccess = 0;
          tfResults.forEach(r => {
            tfTotal += r.total;
            tfSuccess += r.success;
          });
          p2Total += tfTotal;
          p2Success += tfSuccess;
          
          const tfElapsed = ((Date.now() - tfStart) / 1000).toFixed(1);
          console.log('[PHASE 2] ' + tf + '분봉 전체 완료! (' + tfSuccess + '/' + tfTotal + ', ' + tfElapsed + '초)');
          
          // ════════════════════════════════════════════════════════════════
          //  개별 거래소 완료 시마다 이미 브로드캐스트됨
          // - 여기서는 캔들 저장만 수행 (브로드캐스트는 위에서 처리됨)
          // ════════════════════════════════════════════════════════════════
          saveMultiTfCandleStore();
          
          // 최종 확인용 브로드캐스트 (누락 방지)
          try {
            updateGlobalMomentumCaches();
            broadcastToTimeframe(tf);
            console.log('[UI]  ' + tf + '분봉 → Phase 2 전체 완료 최종 브로드캐스트!');
          } catch (broadcastErr) {
            console.error('[UI] ' + tf + '분 브로드캐스트 오류:', broadcastErr.message);
          }
        }
        
        const phase2Elapsed = ((Date.now() - phase2Start) / 1000).toFixed(1);
        
        console.log('');
        console.log('═══════════════════════════════════════════════════════════════');
        console.log('[PHASE 2 완료!] 모든 타임프레임 백그라운드 수집 완료');
        console.log('   ⏱️ 총 소요 시간: ' + phase2Elapsed + '초');
        console.log('   총 성공: ' + p2Success + '/' + p2Total);
        console.log('═══════════════════════════════════════════════════════════════');
        
      } catch (phase2Err) {
        console.error('[PHASE 2] 백그라운드 수집 오류:', phase2Err.message);
      }
    })();  // 즉시 실행, await 없음!
  }
  
  // ────────────────────────────────────────
  // Phase 1 완료 기준 리턴 (Phase 2는 백그라운드)
  // ────────────────────────────────────────
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('[OK]  Multi-Timeframe Backfill Phase 1 완료!');
  console.log('   현재 타임프레임(' + currentTf + '분) 즉시 사용 가능');
  console.log('   나머지 ' + phase2Timeframes.length + '개 타임프레임: 백그라운드 수집 중');
  console.log('   ⏱️ Phase 1 소요 시간: ' + elapsed + '초');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('');
  
  return { total: totalRequests, success: successCount, full: fullCount, incremental: incrementalCount };
}

//  Multi-TF 캔들 저장소 파일 저장
//  파일 저장 쓰로틀링 플래그
//  거래소별 분할 저장 (Invalid string length 에러 해결)
let isSavingMultiTf = false;
const MULTI_TF_EXCHANGES = ['upbit', 'bithumb', 'binance_spot', 'binance_futures', 'okx_spot', 'okx_futures'];

function saveMultiTfCandleStore() {
  //  저장 중이면 스킵 (쓰로틀링)
  if (isSavingMultiTf) {
    console.log('[SAVE]  Multi-TF 저장 스킵 (이전 저장 진행 중)');
    return;
  }
  
  isSavingMultiTf = true;
  
  //  거래소별로 분할 저장 (Invalid string length 에러 방지)
  let savedCount = 0;
  let errorCount = 0;
  let totalSymbols = 0;
  
  const savePromises = MULTI_TF_EXCHANGES.map(exchange => {
    return new Promise((resolve) => {
      try {
        const exchangeData = CandleManager.multiTfStore[exchange];
        if (!exchangeData || Object.keys(exchangeData).length === 0) {
          resolve({ exchange, success: true, symbols: 0, candles: 0 });
          return;
        }
        
        // 해당 거래소 데이터만 추출
        const dataToSave = {};
        let symbolCount = 0;
        let candleCount = 0;
        
        Object.keys(exchangeData).forEach(symbol => {
          dataToSave[symbol] = {};
          Object.keys(exchangeData[symbol]).forEach(tf => {
            const data = exchangeData[symbol][tf];
            if (data && data.candles && data.candles.length > 0) {
              dataToSave[symbol][tf] = {
                candles: data.candles.slice(0, 400),  // 400개만 저장
                updatedAt: data.updatedAt,
                backfilled: data.backfilled  //  backfilled 플래그 저장!
              };
              candleCount += Math.min(data.candles.length, 400);
            }
          });
          if (Object.keys(dataToSave[symbol]).length > 0) {
            symbolCount++;
          } else {
            delete dataToSave[symbol];  // 빈 심볼 제거
          }
        });
        
        if (symbolCount === 0) {
          resolve({ exchange, success: true, symbols: 0, candles: 0 });
          return;
        }
        
        //  거래소별 파일로 저장
        const savePath = path.join(DATA_DIR, 'multi_tf_' + exchange + '.json');
        const jsonData = JSON.stringify(dataToSave);
        
        fs.writeFile(savePath, jsonData, 'utf8', (err) => {
          if (err) {
            console.error('[ERROR]  ' + exchange + ' Multi-TF 저장 실패:', err.message);
            resolve({ exchange, success: false, symbols: 0, candles: 0 });
          } else {
            resolve({ exchange, success: true, symbols: symbolCount, candles: candleCount, size: jsonData.length });
          }
        });
      } catch (error) {
        console.error('[ERROR]  ' + exchange + ' Multi-TF 저장 준비 실패:', error.message);
        resolve({ exchange, success: false, symbols: 0, candles: 0 });
      }
    });
  });
  
  // 모든 저장 완료 대기
  Promise.all(savePromises).then(results => {
    isSavingMultiTf = false;
    
    results.forEach(r => {
      if (r.success) {
        savedCount++;
        totalSymbols += r.symbols;
      } else {
        errorCount++;
      }
    });
    
    const totalSizeMB = results.reduce((sum, r) => sum + (r.size || 0), 0) / (1024 * 1024);
    
    if (errorCount === 0) {
      console.log('[SAVE]  Multi-TF 분할 저장 완료 (' + savedCount + '개 거래소, ' + totalSymbols + '개 심볼, ' + totalSizeMB.toFixed(2) + 'MB)');
    } else {
      console.log('[SAVE]  Multi-TF 분할 저장 부분 완료 (성공: ' + savedCount + ', 실패: ' + errorCount + ')');
    }
  }).catch(err => {
    isSavingMultiTf = false;
    console.error('[ERROR]  Multi-TF 저장 Promise 오류:', err.message);
  });
}

//  Multi-TF 캔들 저장소 파일 복원
//  거래소별 분할 파일 로드 + 레거시 단일 파일 마이그레이션
function loadMultiTfCandleStore() {
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('[LOAD]  Multi-TF 캔들 캐시 로드 시작...');
  console.log('═══════════════════════════════════════════════════════════════');
  
  try {
    let totalSymbols = 0;
    let loadedExchanges = 0;
    let failedExchanges = [];
    
    //  디버그: 타임프레임별 캔들 수 집계
    const tfStats = {};
    
    //  1단계: 거래소별 분할 파일 로드 시도
    MULTI_TF_EXCHANGES.forEach(exchange => {
      const splitPath = path.join(DATA_DIR, 'multi_tf_' + exchange + '.json');
      console.log('   [DEBUG] ' + exchange + ' 파일 확인: ' + splitPath);
      console.log('      파일 존재: ' + fs.existsSync(splitPath));
      
      if (fs.existsSync(splitPath)) {
        try {
          const stats = fs.statSync(splitPath);
          console.log('      파일 크기: ' + (stats.size / 1024 / 1024).toFixed(2) + 'MB');
          console.log('      최종 수정: ' + stats.mtime.toISOString());
          
          const data = fs.readFileSync(splitPath, 'utf8');
          const parsed = JSON.parse(data);
          
          if (!CandleManager.multiTfStore[exchange]) {
            CandleManager.multiTfStore[exchange] = {};
          }
          
          let symbolCount = 0;
          let candleCountByTf = {};
          
          Object.keys(parsed).forEach(symbol => {
            CandleManager.multiTfStore[exchange][symbol] = parsed[symbol];
            symbolCount++;
            
            //  타임프레임별 캔들 수 집계
            Object.keys(parsed[symbol] || {}).forEach(tf => {
              const candleCount = parsed[symbol][tf]?.candles?.length || 0;
              if (!candleCountByTf[tf]) candleCountByTf[tf] = { total: 0, symbols: 0, min: Infinity, max: 0 };
              candleCountByTf[tf].total += candleCount;
              candleCountByTf[tf].symbols++;
              if (candleCount < candleCountByTf[tf].min) candleCountByTf[tf].min = candleCount;
              if (candleCount > candleCountByTf[tf].max) candleCountByTf[tf].max = candleCount;
            });
          });
          
          totalSymbols += symbolCount;
          loadedExchanges++;
          
          //  거래소별 상세 로그
          console.log('   [OK] ' + exchange + ' 로드 완료 (' + symbolCount + '개 심볼)');
          Object.keys(candleCountByTf).sort((a, b) => Number(a) - Number(b)).forEach(tf => {
            const stat = candleCountByTf[tf];
            const avg = Math.round(stat.total / stat.symbols);
            const has360 = stat.min >= 360 ? 'OK' : 'WARN(min=' + stat.min + ')';
            console.log('      ' + tf + '분봉: ' + stat.symbols + '심볼, avg=' + avg + ', min=' + stat.min + ', max=' + stat.max + ' [' + has360 + ']');
            
            // 전체 통계에 누적
            if (!tfStats[tf]) tfStats[tf] = { total: 0, symbols: 0, min: Infinity, max: 0 };
            tfStats[tf].total += stat.total;
            tfStats[tf].symbols += stat.symbols;
            if (stat.min < tfStats[tf].min) tfStats[tf].min = stat.min;
            if (stat.max > tfStats[tf].max) tfStats[tf].max = stat.max;
          });
          
        } catch (parseErr) {
          console.error('[ERROR]  ' + exchange + ' Multi-TF 파싱 실패:', parseErr.message);
          failedExchanges.push(exchange);
        }
      } else {
        console.log('      [WARN] 파일 없음! → 이 거래소는 전체 백필 필요');
      }
    });
    
    //  2단계: 분할 파일이 하나도 없으면 레거시 단일 파일 시도
    if (loadedExchanges === 0) {
      const legacyPath = path.join(DATA_DIR, 'multi_tf_candle_store.json');
      if (fs.existsSync(legacyPath)) {
        console.log('[MIGRATE]  레거시 단일 파일 발견, 마이그레이션 시도...');
        try {
          const data = fs.readFileSync(legacyPath, 'utf8');
          const parsed = JSON.parse(data);
          
          Object.keys(parsed).forEach(exchange => {
            if (!CandleManager.multiTfStore[exchange]) {
              CandleManager.multiTfStore[exchange] = {};
            }
            Object.keys(parsed[exchange]).forEach(symbol => {
              CandleManager.multiTfStore[exchange][symbol] = parsed[exchange][symbol];
              totalSymbols++;
            });
          });
          
          console.log('[MIGRATE]  레거시 복원 완료 (' + totalSymbols + '개 심볼)');
          console.log('[MIGRATE]  다음 저장 시 분할 파일로 자동 마이그레이션됩니다.');
          
          // 마이그레이션 후 레거시 파일 백업 (삭제하지 않음)
          const backupPath = path.join(DATA_DIR, 'multi_tf_candle_store.json.bak');
          if (!fs.existsSync(backupPath)) {
            fs.copyFileSync(legacyPath, backupPath);
            console.log('[MIGRATE]  레거시 파일 백업 완료: ' + backupPath);
          }
          
          return true;
        } catch (legacyErr) {
          console.error('[ERROR]  레거시 파일 복원 실패:', legacyErr.message);
          return false;
        }
      }
      
      console.log('[WARN]  Multi-TF 캔들 파일 전혀 없음! → 전체 백필 필요');
      console.log('      DATA_DIR: ' + DATA_DIR);
      console.log('      예상 파일: multi_tf_upbit.json, multi_tf_bithumb.json, ...');
      return false;
    }
    
    //  전체 통계 요약
    console.log('');
    console.log('   [SUMMARY] 전체 타임프레임별 캔들 현황:');
    Object.keys(tfStats).sort((a, b) => Number(a) - Number(b)).forEach(tf => {
      const stat = tfStats[tf];
      const avg = Math.round(stat.total / stat.symbols);
      const status = stat.min >= 360 ? 'OK' : 'NEED_BACKFILL(min=' + stat.min + ')';
      console.log('      ' + tf + '분봉: ' + stat.symbols + '심볼, avg=' + avg + ' [' + status + ']');
    });
    
    //  3단계: 결과 로그
    if (failedExchanges.length > 0) {
      console.log('[LOAD]  Multi-TF 분할 복원 부분 완료 (' + loadedExchanges + '개 성공, 실패: ' + failedExchanges.join(', ') + ')');
    } else {
      console.log('[LOAD]  Multi-TF 분할 복원 완료 (' + loadedExchanges + '개 거래소, ' + totalSymbols + '개 심볼)');
    }
    
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('');
    
    //  글로벌 거래소 1분봉을 store에 동기화
    // - multiTfStore에서 로드한 1분봉을 CandleManager.store에도 복사
    // - 글로벌 거래소 모멘텀 계산은 store를 참조하기 때문에 필요
    const globalExchanges = ['binance_spot', 'binance_futures', 'okx_spot', 'okx_futures'];
    let syncedCount = 0;
    globalExchanges.forEach(exchange => {
      if (CandleManager.multiTfStore[exchange]) {
        if (!CandleManager.store[exchange]) CandleManager.store[exchange] = {};
        Object.keys(CandleManager.multiTfStore[exchange]).forEach(symbol => {
          const oneMinData = CandleManager.multiTfStore[exchange][symbol]?.[1];
          if (oneMinData && oneMinData.candles && oneMinData.candles.length > 0) {
            // store에 1분봉 데이터 복사
            CandleManager.store[exchange][symbol] = {
              timeframe: 1,
              candles: oneMinData.candles.slice(),  // 복사
              updatedAt: oneMinData.updatedAt || Date.now(),
              backfilled: oneMinData.candles.length >= MIN_CANDLES_FOR_MOMENTUM
            };
            syncedCount++;
          }
        });
      }
    });
    
    if (syncedCount > 0) {
      console.log('[SYNC]  multiTfStore → store 1분봉 동기화 완료 (' + syncedCount + '개 심볼)');
    }
    
    return loadedExchanges > 0;
  } catch (error) {
    console.error('[ERROR]  Multi-TF 캔들 복원 실패:', error.message);
    return false;
  }
}

// ---
//  Multi-TF 캔들 증분 갱신 (30분마다 실행)
// - 업비트/빗썸 포함한 모든 거래소의 Multi-TF 캔들을 최신화
// - 증분 수집만 수행 (전체 수집은 backfillMultiTimeframeCandles에서)
// ---
async function updateMultiTfCandlesIncremental() {
  if (!marketsLoaded) {
    console.log('⏳  Multi-TF 증분 갱신 대기 중 (마켓 로딩 필요)...');
    return;
  }
  
  console.log('[SYNC]  Multi-TF 캔들 증분 갱신 시작...');
  const startTime = Date.now();
  let successCount = 0;
  let totalCount = 0;
  
  // 업비트 증분 갱신
  for (const timeframe of MULTI_TF_BACKFILL_TIMEFRAMES) {
    for (const symbol of UPBIT_MARKETS) {
      try {
        const existingCount = CandleManager.getMultiTfCandleCount('upbit', symbol, timeframe);
        if (existingCount >= MIN_CANDLES_FOR_MOMENTUM) {
          // 증분 수집만
          const unit = UPBIT_INTERVAL_MAP[timeframe] || timeframe;
          const url = 'https://api.upbit.com/v1/candles/minutes/' + unit + '?market=KRW-' + symbol + '&count=' + MULTI_TF_INCREMENTAL_COUNT;
          const response = await UpbitApiScheduler.request(url);
          
          if (response.data && Array.isArray(response.data) && response.data.length > 0) {
            const candles = response.data.map(c => ({
              timestamp: new Date(c.candle_date_time_utc).getTime(),
              open: c.opening_price, high: c.high_price, low: c.low_price, close: c.trade_price,
              volume: c.candle_acc_trade_volume,
              high_price: c.high_price, low_price: c.low_price
            }));
            CandleManager.initializeMultiTfCandles('upbit', symbol, timeframe, candles);
            successCount++;
          }
        }
        totalCount++;
      } catch (err) {
        // 스킵
      }
    }
  }
  
  // 빗썸 증분 갱신
  for (const timeframe of MULTI_TF_BACKFILL_TIMEFRAMES) {
    for (const symbol of BITHUMB_MARKETS) {
      try {
        const existingCount = CandleManager.getMultiTfCandleCount('bithumb', symbol, timeframe);
        if (existingCount >= MIN_CANDLES_FOR_MOMENTUM) {
          const candles = await fetchBithumbCandlesMultiTf(symbol, MULTI_TF_INCREMENTAL_COUNT, timeframe);
          if (candles && candles.length > 0) {
            CandleManager.initializeMultiTfCandles('bithumb', symbol, timeframe, candles);
            successCount++;
          }
        }
        totalCount++;
        await sleep(100);  // 빗썸 Rate Limit 대응
      } catch (err) {
        // 스킵
      }
    }
  }
  
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log('[OK]  Multi-TF 증분 갱신 완료! (' + successCount + '/' + totalCount + ', ' + elapsed + '초)');
  
  // 파일 저장
  saveMultiTfCandleStore();
}

//  Multi-TF 캔들 확보 상태 체크
function checkMultiTfCandleStatus() {
  const status = {};
  const exchanges = ['binance_spot', 'binance_futures', 'okx_spot', 'okx_futures', 'upbit', 'bithumb'];  //  국내 거래소 추가
  
  exchanges.forEach(exchange => {
    status[exchange] = {};
    MULTI_TF_BACKFILL_TIMEFRAMES.forEach(tf => {
      let totalSymbols = 0;
      let sufficientSymbols = 0;
      
      const store = CandleManager.multiTfStore[exchange];
      if (store) {
        Object.keys(store).forEach(symbol => {
          totalSymbols++;
          if (store[symbol]?.[tf]?.candles?.length >= MIN_CANDLES_FOR_MOMENTUM) {
            sufficientSymbols++;
          }
        });
      }
      
      status[exchange][tf] = {
        total: totalSymbols,
        sufficient: sufficientSymbols,
        pass: totalSymbols > 0 && sufficientSymbols === totalSymbols
      };
    });
  });
  
  return status;
}

// ---
// 캔들 캐시 파일 저장/복원
// ---
function saveCandleCacheToFile() {
  try {
    const cacheData = {};
    bithumbCandleCache.forEach((candles, symbol) => { cacheData[symbol] = candles; });
    fs.writeFileSync(CANDLE_CACHE_FILE, JSON.stringify(cacheData), 'utf8');
    console.log('[SAVE] 캔들 캐시 파일 저장 완료');
  } catch (error) {
    console.error('[ERROR] 캔들 캐시 파일 저장 실패:', error.message);
  }
}

function loadCandleCacheFromFile() {
  try {
    if (fs.existsSync(CANDLE_CACHE_FILE)) {
      const data = fs.readFileSync(CANDLE_CACHE_FILE, 'utf8');
      const cacheData = JSON.parse(data);
      Object.keys(cacheData).forEach(symbol => { bithumbCandleCache.set(symbol, cacheData[symbol]); });
      console.log('[DIR] 캔들 캐시 파일 복원 완료 (' + bithumbCandleCache.size + '개 심볼)');
    } else {
      console.log('[DIR] 캔들 캐시 파일 없음 - 새로 시작');
    }
  } catch (error) {
    console.error('[ERROR] 캔들 캐시 파일 복원 실패:', error.message);
  }
}

// ---
//  빗썸 1시간봉 캐시 파일 저장/복원 (4시간봉 합성용)
// ---
function save1HourCacheToFile() {
  try {
    const cacheData = {};
    bithumb1HourCache.forEach((candles, symbol) => { cacheData[symbol] = candles; });
    fs.writeFileSync(BITHUMB_1HOUR_CACHE_FILE, JSON.stringify(cacheData), 'utf8');
    console.log('[SAVE] 빗썸 1시간봉 캐시 파일 저장 완료 (' + bithumb1HourCache.size + '개 심볼)');
  } catch (error) {
    console.error('[ERROR] 빗썸 1시간봉 캐시 파일 저장 실패:', error.message);
  }
}

function load1HourCacheFromFile() {
  try {
    if (fs.existsSync(BITHUMB_1HOUR_CACHE_FILE)) {
      const data = fs.readFileSync(BITHUMB_1HOUR_CACHE_FILE, 'utf8');
      const cacheData = JSON.parse(data);
      Object.keys(cacheData).forEach(symbol => { bithumb1HourCache.set(symbol, cacheData[symbol]); });
      console.log('[DIR] 빗썸 1시간봉 캐시 파일 복원 완료 (' + bithumb1HourCache.size + '개 심볼)');
    } else {
      console.log('[DIR] 빗썸 1시간봉 캐시 파일 없음 - 새로 시작');
    }
  } catch (error) {
    console.error('[ERROR] 빗썸 1시간봉 캐시 파일 복원 실패:', error.message);
  }
}

// ---
//  글로벌 거래소 캔들 파일 저장/복원 (스마트 초기화용)
// - CandleManager.store의 글로벌 거래소 데이터를 파일로 저장/복원
// - 서버 재시작 시 과거 데이터 유지 (이어달리기 개념)
// ---
function saveGlobalCandleStoreToFile() {
  try {
    const globalExchanges = ['binance_spot', 'binance_futures', 'okx_spot', 'okx_futures'];
    const storeData = {
      timestamp: Date.now(),
      exchanges: {}
    };
    
    let totalSymbols = 0;
    let totalCandles = 0;
    
    globalExchanges.forEach(exchange => {
      if (CandleManager.store[exchange]) {
        storeData.exchanges[exchange] = {};
        const symbols = Object.keys(CandleManager.store[exchange]);
        
        symbols.forEach(symbol => {
          const data = CandleManager.store[exchange][symbol];
          if (data && data.candles && data.candles.length > 0) {
            // 최대 2000개만 저장 (파일 크기 관리)
            storeData.exchanges[exchange][symbol] = {
              candles: data.candles.slice(0, 2000),
              updatedAt: data.updatedAt
            };
            totalSymbols++;
            totalCandles += Math.min(data.candles.length, 2000);
          }
        });
      }
    });
    
    if (totalSymbols > 0) {
      fs.writeFileSync(GLOBAL_CANDLE_STORE_FILE, JSON.stringify(storeData), 'utf8');
      console.log('[SAVE]  글로벌 캔들 저장 완료 (' + totalSymbols + '개 심볼, ' + totalCandles + '개 캔들)');
    }
  } catch (error) {
    console.error('[ERROR] 글로벌 캔들 저장 실패:', error.message);
  }
}

function loadGlobalCandleStoreFromFile() {
  try {
    if (!fs.existsSync(GLOBAL_CANDLE_STORE_FILE)) {
      console.log('[DIR]  글로벌 캔들 파일 없음 - Backfill로 초기화 필요');
      return { loaded: false, symbols: 0 };
    }
    
    const data = fs.readFileSync(GLOBAL_CANDLE_STORE_FILE, 'utf8');
    const storeData = JSON.parse(data);
    
    // 유효성 검사: 24시간 이내 데이터만 유효
    const fileAge = Date.now() - (storeData.timestamp || 0);
    const maxAge = 24 * 60 * 60 * 1000;  // 24시간
    
    if (fileAge > maxAge) {
      console.log('[DIR]  글로벌 캔들 파일 만료됨 (' + Math.round(fileAge / 3600000) + '시간 전) - Backfill 필요');
      return { loaded: false, symbols: 0 };
    }
    
    let totalSymbols = 0;
    let totalCandles = 0;
    let sufficientSymbols = 0;  //  360개 이상 가진 심볼 수
    
    const globalExchanges = ['binance_spot', 'binance_futures', 'okx_spot', 'okx_futures'];
    
    globalExchanges.forEach(exchange => {
      if (storeData.exchanges && storeData.exchanges[exchange]) {
        if (!CandleManager.store[exchange]) {
          CandleManager.store[exchange] = {};
        }
        
        const symbols = Object.keys(storeData.exchanges[exchange]);
        symbols.forEach(symbol => {
          const saved = storeData.exchanges[exchange][symbol];
          if (saved && saved.candles && saved.candles.length > 0) {
            //  360개 이상이면 backfilled: true, 미만이면 false (아직 수집 필요)
            const hasEnoughCandles = saved.candles.length >= MIN_CANDLES_FOR_MOMENTUM;
            
            CandleManager.store[exchange][symbol] = {
              timeframe: 1,
              candles: saved.candles,
              updatedAt: saved.updatedAt || Date.now(),
              backfilled: hasEnoughCandles  //  조건부 설정
            };
            totalSymbols++;
            totalCandles += saved.candles.length;
            if (hasEnoughCandles) sufficientSymbols++;
          }
        });
      }
    });
    
    console.log('[DIR]  글로벌 캔들 복원 완료 (' + totalSymbols + '개 심볼, ' + totalCandles + '개 캔들, 충분: ' + sufficientSymbols + '개)');
    return { loaded: true, symbols: totalSymbols, candles: totalCandles, sufficient: sufficientSymbols };
    
  } catch (error) {
    console.error('[ERROR] 글로벌 캔들 복원 실패:', error.message);
    return { loaded: false, symbols: 0 };
  }
}

// ---
// 업비트 24시간 전 가격 캐시 파일 저장/복원 (수정 1)
// ---
function saveUpbitPriceCacheToFile() {
  try {
    const cacheData = {};
    upbit24hPriceCache.forEach((price, symbol) => { cacheData[symbol] = price; });
    fs.writeFileSync(UPBIT_PRICE_CACHE_FILE, JSON.stringify(cacheData), 'utf8');
    console.log('[SAVE] 업비트 가격 캐시 파일 저장 완료 (' + upbit24hPriceCache.size + '개)');
  } catch (error) {
    console.error('[ERROR] 업비트 가격 캐시 파일 저장 실패:', error.message);
  }
}

function loadUpbitPriceCacheFromFile() {
  try {
    if (fs.existsSync(UPBIT_PRICE_CACHE_FILE)) {
      const data = fs.readFileSync(UPBIT_PRICE_CACHE_FILE, 'utf8');
      const cacheData = JSON.parse(data);
      Object.keys(cacheData).forEach(symbol => { upbit24hPriceCache.set(symbol, cacheData[symbol]); });
      console.log('[DIR] 업비트 가격 캐시 파일 복원 완료 (' + upbit24hPriceCache.size + '개)');
      return true;
    } else {
      console.log('[DIR] 업비트 가격 캐시 파일 없음 - API로 초기화 필요');
      return false;
    }
  } catch (error) {
    console.error('[ERROR] 업비트 가격 캐시 파일 복원 실패:', error.message);
    return false;
  }
}

// ---
//  CandleManager 파일 저장/복원 (기존 함수 대체)
// ---
function saveUpbitCandleCacheToFile() {
  // CandleManager 통합 저장 사용
  CandleManager.saveToFile();
}

function loadUpbitCandleCacheFromFile() {
  // CandleManager 통합 복원 사용
  const result = CandleManager.loadFromFile();
  
  //  Multi-TF 캔들도 함께 복원 (스마트 증분 수집 핵심!)
  CandleManager.loadMultiTfFromFile();
  
  return result;
}

// ---
// [문제 1 해결] coinData 스냅샷 저장/로드 (서버 재시작 시 즉시 복원)
// ---
function saveCoinDataSnapshot() {
  try {
    // isDummy 제외하고 저장
    const dataToSave = coinData.filter(c => !c.isDummy);
    if (dataToSave.length === 0) {
      return; // 빈 데이터는 저장하지 않음
    }
    
    fs.writeFileSync(COIN_DATA_SNAPSHOT_FILE, JSON.stringify(dataToSave), 'utf8');
    console.log('[SNAP] coinData 스냅샷 저장 완료 (' + dataToSave.length + '개 코인)');
    lastSnapshotSaveTime = Date.now();
  } catch (error) {
    console.error('[ERROR] coinData 스냅샷 저장 실패:', error.message);
  }
}

function loadCoinDataSnapshot() {
  try {
    if (fs.existsSync(COIN_DATA_SNAPSHOT_FILE)) {
      const data = fs.readFileSync(COIN_DATA_SNAPSHOT_FILE, 'utf8');
      const snapshot = JSON.parse(data);
      
      if (Array.isArray(snapshot) && snapshot.length > 0) {
        //  스냅샷 로드 시 해외 거래소 심볼 세탁 (Sanitization)
        // 이전 버전에서 저장된 오염된 데이터(긴 심볼명) 정리
        //  Bugfix: coin.exchangeId → coin.exchange (속성명 오타 수정)
        //  강화: 하이픈 유무 모두 처리 (ECALLUSDTSWAP, ECALL-USDT-SWAP 둘 다)
        //  모멘텀 값을 undefined로 초기화 (Calc... 표시용)
        const sanitizedSnapshot = snapshot.map(coin => {
          const exchangeId = coin.exchange;
          let sanitizedSymbol = coin.symbol;
          
          // 해외 거래소 심볼 정규화 (접미사 제거)
          //  두 가지 형태 모두 처리: 하이픈 있는 형태 + 하이픈 없는 형태
          if (exchangeId === 'BINANCE_SPOT' || exchangeId === 'BINANCE_FUTURES') {
            // 'BTCUSDT' → 'BTC', 'BTC-USDT' → 'BTC'
            sanitizedSymbol = sanitizedSymbol.replace(/-?USDT$/, '');
          } else if (exchangeId === 'OKX_SPOT') {
            // 'BTC-USDT' → 'BTC', 'BTCUSDT' → 'BTC'
            sanitizedSymbol = sanitizedSymbol.replace(/-?USDT$/, '');
          } else if (exchangeId === 'OKX_FUTURES') {
            //  세 가지 형태 모두 처리:
            // 'BTC-USDT-SWAP' → 'BTC' (정상 형태)
            // 'BTCUSDTSWAP' → 'BTC' (하이픈 제거된 오염 형태)
            // 'BTCUSDT.P' → 'BTC' (혹시 모를 형태)
            sanitizedSymbol = sanitizedSymbol
              .replace(/-USDT-SWAP$/, '')   // 하이픈 있는 형태
              .replace(/USDTSWAP$/, '')     // 하이픈 없는 오염 형태
              .replace(/USDT\.P$/, '')      // .P 형태
              .replace(/-?USDT$/, '');      // 남은 USDT 제거
          }
          
          // ---
          //  모멘텀 값을 undefined로 초기화
          // - 서버 재시작 시 메모리의 캔들/모멘텀 캐시가 비어있음
          // - undefined로 설정하면 클라이언트가 "Calc..." (로딩 중) 표시
          // - 이후 캐시 로드 및 계산 완료 시 올바른 값으로 자연스럽게 전환
          // ---
          return { 
            ...coin, 
            symbol: sanitizedSymbol, 
            upProbability: undefined, 
            downProbability: undefined 
          };
        });
        
        // 세탁된 스냅샷으로 coinData 대체
        coinData = sanitizedSnapshot;
        console.log('[SNAP] coinData 스냅샷 복원 완료! (' + coinData.length + '개 코인, 심볼 정규화 + 모멘텀 undefined 초기화)');
        return true;
      } else {
        console.log('[SNAP] coinData 스냅샷 비어있음 - 새로 시작');
        return false;
      }
    } else {
      console.log('[SNAP] coinData 스냅샷 파일 없음 - 새로 시작');
      return false;
    }
  } catch (error) {
    console.error('[ERROR] coinData 스냅샷 복원 실패:', error.message);
    return false;
  }
}

// 10초마다 스냅샷 저장 체크 (throttle)
function maybeSaveCoinDataSnapshot() {
  const now = Date.now();
  if (now - lastSnapshotSaveTime >= SNAPSHOT_SAVE_INTERVAL) {
    saveCoinDataSnapshot();
  }
}

// ---
//  모멘텀 캐시 파일 저장/로드 (서버 재시작 시 즉시 복원)
//  글로벌 거래소(바이낸스, OKX) 캐시 저장 추가!
// ---
function saveMomentumCacheToFile() {
  try {
    // Map을 JSON 직렬화 가능한 객체로 변환
    const cacheData = {
      upbit: {},
      bithumb: {},
      global: {},  //  글로벌 거래소 추가!
      savedAt: Date.now()
    };
    
    // 업비트 모멘텀 캐시 변환
    ALLOWED_TIMEFRAMES.forEach(tf => {
      if (momentumCacheMap.upbit[tf] && momentumCacheMap.upbit[tf].size > 0) {
        cacheData.upbit[tf] = {};
        momentumCacheMap.upbit[tf].forEach((momentum, symbol) => {
          cacheData.upbit[tf][symbol] = momentum;
        });
      }
    });
    
    // 빗썸 모멘텀 캐시 변환
    ALLOWED_TIMEFRAMES.forEach(tf => {
      if (momentumCacheMap.bithumb[tf] && momentumCacheMap.bithumb[tf].size > 0) {
        cacheData.bithumb[tf] = {};
        momentumCacheMap.bithumb[tf].forEach((momentum, symbol) => {
          cacheData.bithumb[tf][symbol] = momentum;
        });
      }
    });
    
    // ════════════════════════════════════════════════════════════════
    //  글로벌 거래소 모멘텀 캐시 변환 (바이낸스, OKX)
    // - globalMomentumCache[timeframe].get('BINANCE_SPOT:BTC') 형태
    // ════════════════════════════════════════════════════════════════
    ALLOWED_TIMEFRAMES.forEach(tf => {
      if (globalMomentumCache[tf] && globalMomentumCache[tf].size > 0) {
        cacheData.global[tf] = {};
        globalMomentumCache[tf].forEach((momentum, globalKey) => {
          // globalKey = 'BINANCE_SPOT:BTC' 형태
          cacheData.global[tf][globalKey] = momentum;
        });
      }
    });
    
    fs.writeFileSync(MOMENTUM_CACHE_FILE, JSON.stringify(cacheData), 'utf8');
    
    // 저장된 항목 수 계산
    let upbitCount = 0, bithumbCount = 0, globalCount = 0;
    Object.keys(cacheData.upbit).forEach(tf => {
      upbitCount += Object.keys(cacheData.upbit[tf]).length;
    });
    Object.keys(cacheData.bithumb).forEach(tf => {
      bithumbCount += Object.keys(cacheData.bithumb[tf]).length;
    });
    Object.keys(cacheData.global).forEach(tf => {
      globalCount += Object.keys(cacheData.global[tf]).length;
    });
    
    console.log('[SAVE]  모멘텀 캐시 파일 저장 완료 (업비트: ' + upbitCount + ', 빗썸: ' + bithumbCount + ', 글로벌: ' + globalCount + ')');
    lastMomentumCacheSaveTime = Date.now();
  } catch (error) {
    console.error('[ERROR] 모멘텀 캐시 파일 저장 실패:', error.message);
  }
}

function loadMomentumCacheFromFile() {
  try {
    if (fs.existsSync(MOMENTUM_CACHE_FILE)) {
      const data = fs.readFileSync(MOMENTUM_CACHE_FILE, 'utf8');
      const cacheData = JSON.parse(data);
      
      let upbitCount = 0, bithumbCount = 0, globalCount = 0;
      
      // 업비트 모멘텀 캐시 복원
      if (cacheData.upbit) {
        Object.keys(cacheData.upbit).forEach(tf => {
          const tfNum = Number(tf);
          if (!momentumCacheMap.upbit[tfNum]) {
            momentumCacheMap.upbit[tfNum] = new Map();
          }
          Object.keys(cacheData.upbit[tf]).forEach(symbol => {
            momentumCacheMap.upbit[tfNum].set(symbol, cacheData.upbit[tf][symbol]);
            // 현재 타임프레임이면 기존 캐시에도 반영
            if (tfNum === momentumTimeframe) {
              upbitMomentumCache.set(symbol, cacheData.upbit[tf][symbol]);
            }
            upbitCount++;
          });
        });
      }
      
      // 빗썸 모멘텀 캐시 복원
      if (cacheData.bithumb) {
        Object.keys(cacheData.bithumb).forEach(tf => {
          const tfNum = Number(tf);
          if (!momentumCacheMap.bithumb[tfNum]) {
            momentumCacheMap.bithumb[tfNum] = new Map();
          }
          Object.keys(cacheData.bithumb[tf]).forEach(symbol => {
            momentumCacheMap.bithumb[tfNum].set(symbol, cacheData.bithumb[tf][symbol]);
            // 현재 타임프레임이면 기존 캐시에도 반영
            if (tfNum === momentumTimeframe) {
              bithumbMomentumCache.set(symbol, cacheData.bithumb[tf][symbol]);
            }
            bithumbCount++;
          });
        });
      }
      
      // ════════════════════════════════════════════════════════════════
      //  글로벌 거래소 모멘텀 캐시 복원 (바이낸스, OKX)
      // - globalKey = 'BINANCE_SPOT:BTC' 형태
      // ════════════════════════════════════════════════════════════════
      if (cacheData.global) {
        Object.keys(cacheData.global).forEach(tf => {
          const tfNum = Number(tf);
          if (!globalMomentumCache[tfNum]) {
            globalMomentumCache[tfNum] = new Map();
          }
          Object.keys(cacheData.global[tf]).forEach(globalKey => {
            const momentum = cacheData.global[tf][globalKey];
            globalMomentumCache[tfNum].set(globalKey, momentum);
            
            // 현재 타임프레임이면 레거시 캐시에도 반영
            // globalKey = 'BINANCE_SPOT:BTC' → exchange = 'BINANCE_SPOT', symbol = 'BTC'
            if (tfNum === momentumTimeframe) {
              const [exchange, symbol] = globalKey.split(':');
              if (exchange === 'BINANCE_SPOT') {
                binanceSpotMomentumCache.set(symbol, momentum);
              } else if (exchange === 'BINANCE_FUTURES') {
                binanceFuturesMomentumCache.set(symbol, momentum);
              } else if (exchange === 'OKX_SPOT') {
                okxSpotMomentumCache.set(symbol, momentum);
              } else if (exchange === 'OKX_FUTURES') {
                okxFuturesMomentumCache.set(symbol, momentum);
              }
            }
            globalCount++;
          });
        });
      }
      
      const savedAt = cacheData.savedAt ? new Date(cacheData.savedAt).toLocaleString('ko-KR') : '알 수 없음';
      console.log('[DIR]  모멘텀 캐시 파일 복원 완료! (업비트: ' + upbitCount + ', 빗썸: ' + bithumbCount + ', 글로벌: ' + globalCount + ', 저장시각: ' + savedAt + ')');
      return true;
    } else {
      console.log('[DIR]  모멘텀 캐시 파일 없음 - 새로 시작');
      return false;
    }
  } catch (error) {
    console.error('[ERROR] 모멘텀 캐시 파일 복원 실패:', error.message);
    return false;
  }
}

// 30초마다 모멘텀 캐시 저장 체크 (throttle)
function maybeSaveMomentumCache() {
  const now = Date.now();
  if (now - lastMomentumCacheSaveTime >= MOMENTUM_CACHE_SAVE_INTERVAL) {
    saveMomentumCacheToFile();
  }
}

// ---
// 빗썸 캔들스틱 API 호출
// ---
async function fetchBithumbCandles(symbol, interval) {
  try {
    const url = 'https://api.bithumb.com/public/candlestick/' + symbol + '_KRW/' + interval;
    const response = await axios.get(url, { timeout: 10000 });
    
    if (response.data && response.data.status === '0000' && response.data.data) {
      const rawData = response.data.data;
      return rawData.map(item => ({
        timestamp: item[0],
        open: parseFloat(item[1]),
        close: parseFloat(item[2]),
        high: parseFloat(item[3]),
        low: parseFloat(item[4]),
        volume: parseFloat(item[5])
      }));
    }
    return [];
  } catch (error) {
    console.error('[ERROR] 빗썸 캔들 조회 오류 (' + symbol + '):', error.message);
    return [];
  }
}

// ---
//  빗썸 5분봉 → 15분봉/4시간봉 합성 함수 (빗썸 전용)
// - 빗썸 캔들 형식: { high, low, open, close, timestamp }
// ---
function aggregateBithumb5MinCandles(candles, targetMinutes) {
  if (!candles || candles.length === 0) return [];
  const candlesPerGroup = targetMinutes / 5;
  if (candlesPerGroup < 1 || !Number.isInteger(candlesPerGroup)) return [];
  
  const aggregated = [];
  for (let i = candles.length - 1; i >= candlesPerGroup - 1; i -= candlesPerGroup) {
    const group = [];
    for (let j = 0; j < candlesPerGroup && (i - j) >= 0; j++) { group.push(candles[i - j]); }
    if (group.length === candlesPerGroup) {
      const oldest = group[group.length - 1];
      const newest = group[0];
      aggregated.unshift({
        timestamp: oldest.timestamp, open: oldest.open, close: newest.close,
        high: Math.max(...group.map(c => c.high)),
        low: Math.min(...group.map(c => c.low)),
        volume: group.reduce((sum, c) => sum + c.volume, 0)
      });
    }
  }
  return aggregated;
}

// ---
// 빗썸 5분봉 캐시 갱신 (5분마다) - 동적 마켓 사용 (명세 1)
// ---
async function updateBithumb5MinCache() {
  // 마켓 로딩 안 됐으면 대기
  if (!marketsLoaded || BITHUMB_MARKETS.length === 0) {
    console.log('⏳ 빗썸 5분봉 캐시 갱신 대기 중... (마켓 로딩 필요)');
    return;
  }
  
  console.log('[DATA] 빗썸 5분봉 캐시 갱신 시작... (' + BITHUMB_MARKETS.length + '개 코인)');
  
  for (const symbol of BITHUMB_MARKETS) {
    try {
      const newCandles = await fetchBithumbCandles(symbol, '5m');
      if (newCandles.length > 0) {
        let existingCandles = bithumbCandleCache.get(symbol) || [];
        const existingTimestamps = new Set(existingCandles.map(c => c.timestamp));
        const uniqueNewCandles = newCandles.filter(c => !existingTimestamps.has(c.timestamp));
        //  spread 제거! push로 in-place 병합
        for (let i = 0; i < uniqueNewCandles.length; i++) {
          existingCandles.push(uniqueNewCandles[i]);
        }
        existingCandles.sort((a, b) => a.timestamp - b.timestamp);
        //  slice 제거! length 직접 조정
        if (existingCandles.length > MAX_CANDLES_PER_SYMBOL) {
          existingCandles = existingCandles.slice(-MAX_CANDLES_PER_SYMBOL);  // 뒤에서 자르기는 slice 필요
        }
        bithumbCandleCache.set(symbol, existingCandles);
      }
      await new Promise(resolve => setTimeout(resolve, 200));
    } catch (error) {
      console.error('[ERROR] 빗썸 5분봉 캐시 갱신 오류 (' + symbol + '):', error.message);
    }
  }
  saveCandleCacheToFile();
  console.log('[OK] 빗썸 5분봉 캐시 갱신 완료');
}

// ---
//  빗썸 1시간봉 캐시 갱신 (30분마다) - 4시간봉 합성용
// - 4시간봉 360개 합성에 1시간봉 1,440개 필요
// - 빗썸 API가 1시간봉을 직접 제공하므로 합성 비율 4:1로 효율적
// ---
async function updateBithumb1HourCache() {
  // 마켓 로딩 안 됐으면 대기
  if (!marketsLoaded || BITHUMB_MARKETS.length === 0) {
    console.log('⏳ 빗썸 1시간봉 캐시 갱신 대기 중... (마켓 로딩 필요)');
    return;
  }
  
  console.log('[DATA] 빗썸 1시간봉 캐시 갱신 시작... (' + BITHUMB_MARKETS.length + '개 코인)');
  
  for (const symbol of BITHUMB_MARKETS) {
    try {
      const newCandles = await fetchBithumbCandles(symbol, '1h');
      if (newCandles.length > 0) {
        let existingCandles = bithumb1HourCache.get(symbol) || [];
        const existingTimestamps = new Set(existingCandles.map(c => c.timestamp));
        const uniqueNewCandles = newCandles.filter(c => !existingTimestamps.has(c.timestamp));
        //  spread 제거! push로 in-place 병합
        for (let i = 0; i < uniqueNewCandles.length; i++) {
          existingCandles.push(uniqueNewCandles[i]);
        }
        existingCandles.sort((a, b) => a.timestamp - b.timestamp);
        //  slice 제거! length 직접 조정 (뒤에서 자르기는 slice 필요)
        if (existingCandles.length > MAX_1HOUR_CANDLES_PER_SYMBOL) {
          existingCandles = existingCandles.slice(-MAX_1HOUR_CANDLES_PER_SYMBOL);
        }
        bithumb1HourCache.set(symbol, existingCandles);
      }
      await new Promise(resolve => setTimeout(resolve, 200));
    } catch (error) {
      console.error('[ERROR] 빗썸 1시간봉 캐시 갱신 오류 (' + symbol + '):', error.message);
    }
  }
  save1HourCacheToFile();
  console.log('[OK] 빗썸 1시간봉 캐시 갱신 완료');
}

// ---
//  업비트 Multi-TF 캔들 조회 함수
// - 업비트는 모든 타임프레임(1,3,5,10,15,30,60,240분)을 직접 지원
// - 이어달리기로 360개 이상 확보
// ---
async function fetchUpbitCandlesMultiTf(symbol, count, timeframe) {
  try {
    const unit = UPBIT_INTERVAL_MAP[timeframe] || timeframe;
    const targetCount = count || (MIN_CANDLES_FOR_MOMENTUM + 10);
    
    // ---
    //  Pagination 구현 (200개 제한 극복)
    // - 업비트 API는 1회 최대 200개 제공
    // - 370개 이상 필요 시 이어달리기로 반복 요청
    // - 최대 5회 루프 (안전장치: 1000개까지 가능)
    // ---
    let allCandles = [];
    let remaining = targetCount;
    let toParam = null;
    
    for (let i = 0; i < 5 && remaining > 0; i++) {
      const requestCount = Math.min(remaining, 200);
      let url = 'https://api.upbit.com/v1/candles/minutes/' + unit + '?market=KRW-' + symbol + '&count=' + requestCount;
      if (toParam) {
        url += '&to=' + toParam;
      }
      
      const response = await UpbitApiScheduler.request(url);
      
      if (!response.data || !Array.isArray(response.data) || response.data.length === 0) {
        break;  // 더 이상 데이터 없음
      }
      
      // 중복 제거 후 병합
      const existingTimestamps = new Set(allCandles.map(c => c.candle_date_time_utc));
      const uniqueCandles = response.data.filter(c => !existingTimestamps.has(c.candle_date_time_utc));
      allCandles = [...allCandles, ...uniqueCandles];
      
      remaining -= uniqueCandles.length;
      
      // 다음 요청을 위한 커서 설정 (가장 오래된 캔들의 시간)
      toParam = response.data[response.data.length - 1].candle_date_time_utc;
      
      // 받은 데이터가 요청 수보다 적으면 더 이상 과거 데이터 없음
      if (response.data.length < requestCount) {
        break;
      }
      
      //  Rate Limit은 UpbitApiScheduler가 관리 → 여기서 sleep 불필요
      // await sleep(200);  // 제거됨
    }
    
    // 업비트 캔들 형식 통일 (high_price, low_price 등)
    return allCandles.map(c => ({
      timestamp: new Date(c.candle_date_time_utc).getTime(),
      open: c.opening_price,
      high: c.high_price,
      low: c.low_price,
      close: c.trade_price,
      volume: c.candle_acc_trade_volume,
      // 업비트 원본 필드도 유지 (모멘텀 계산 호환성)
      high_price: c.high_price,
      low_price: c.low_price,
      opening_price: c.opening_price,
      trade_price: c.trade_price,
      candle_date_time_utc: c.candle_date_time_utc
    }));
    
  } catch (error) {
    console.error('[ERROR] 업비트 Multi-TF 캔들 조회 오류 (' + symbol + ', ' + timeframe + '분):', error.message);
    return [];
  }
}

// ---
//  빗썸 Multi-TF 캔들 조회 함수
// - 빗썸은 1,3,5,10,30,60분만 직접 지원
// - 15분, 240분은 5분봉/1시간봉에서 합성
// ---
async function fetchBithumbCandlesMultiTf(symbol, count, timeframe) {
  try {
    const targetCount = count || (MIN_CANDLES_FOR_MOMENTUM + 10);
    
    // 직접 지원되는 타임프레임
    if (BITHUMB_MULTI_TF_DIRECT.includes(timeframe)) {
      const interval = BITHUMB_INTERVAL_MAP[timeframe];
      if (!interval) return [];
      
      const candles = await fetchBithumbCandles(symbol, interval);
      // 빗썸 API는 기본적으로 최대 1500개 정도 반환
      return candles.slice(0, targetCount);
    }
    
    // 15분봉: 5분봉 3개 합성
    if (timeframe === 15) {
      const candles5m = await fetchBithumbCandles(symbol, '5m');
      if (!candles5m || candles5m.length < 6) return [];
      return aggregateBithumb5MinCandles(candles5m, 15).slice(-targetCount);
    }
    
    // 240분봉(4시간): 1시간봉 4개 합성
    if (timeframe === 240) {
      const candles1h = await fetchBithumbCandles(symbol, '1h');
      if (!candles1h || candles1h.length < 8) return [];
      return aggregateBithumbCandles(candles1h, 60, 240).slice(-targetCount);
    }
    
    return [];
    
  } catch (error) {
    console.error('[ERROR] 빗썸 Multi-TF 캔들 조회 오류 (' + symbol + ', ' + timeframe + '분):', error.message);
    return [];
  }
}

// ---
//  빗썸 캔들 합성 범용 함수 (sourceMinutes → targetMinutes)
// - 5분 → 15분, 60분 → 240분 등 범용 지원
// ---
function aggregateBithumbCandles(candles, sourceMinutes, targetMinutes) {
  if (!candles || candles.length === 0) return [];
  const candlesPerGroup = targetMinutes / sourceMinutes;
  if (candlesPerGroup < 1 || !Number.isInteger(candlesPerGroup)) return [];
  
  const aggregated = [];
  // 최신 → 과거 순서로 그룹핑 (빗썸 캔들은 오래된 것부터 정렬되어 있음)
  for (let i = candles.length - 1; i >= candlesPerGroup - 1; i -= candlesPerGroup) {
    const group = [];
    for (let j = 0; j < candlesPerGroup && (i - j) >= 0; j++) { 
      group.push(candles[i - j]); 
    }
    if (group.length === candlesPerGroup) {
      const oldest = group[group.length - 1];
      const newest = group[0];
      aggregated.unshift({
        timestamp: oldest.timestamp,
        open: oldest.open,
        close: newest.close,
        high: Math.max(...group.map(c => c.high)),
        low: Math.min(...group.map(c => c.low)),
        volume: group.reduce((sum, c) => sum + c.volume, 0)
      });
    }
  }
  return aggregated;
}

// ---
// 업비트 캔들 캐시 갱신 (수정 2: 백그라운드 갱신용)
// - UpbitApiScheduler 사용 (429 에러 근본 해결)
// ---
// ---
//  업비트 캔들 캐시 갱신 - 360개 이어달리기 지원
// - 초기화: 200개 + 160개 = 360개 확보 (이어달리기)
// - 증분: count=3으로 최신 데이터만 받아서 합침
// - Self-Healing: Gap 감지 시 자동 복구
// ---
async function updateUpbitCandleCache() {
  // 마켓 로딩 안 됐으면 대기
  if (!marketsLoaded || UPBIT_MARKETS.length === 0) {
    console.log('⏳ 업비트 캔들 캐시 갱신 대기 중... (마켓 로딩 필요)');
    return;
  }
  
  const startTime = Date.now();
  const safeUnit = momentumTimeframe;
  
  let incrementalCount = 0;  // 증분 업데이트 성공
  let fullFetchCount = 0;    // 전체 요청 (초기화/복구)
  let skipCount = 0;         // 스킵 (에러)
  
  console.log('[DATA]  업비트 캔들 Smart Fetch 시작 (' + UPBIT_MARKETS.length + '개 코인, 타임프레임: ' + safeUnit + '분, 목표: ' + MOMENTUM_CANDLE_COUNT + '개)');
  
  for (const symbol of UPBIT_MARKETS) {
    try {
      // ---
      // [Smart Fetch 로직]
      // 1. 메모리에 데이터가 있고, 타임프레임이 일치하면 → count=3 (증분)
      // 2. 데이터 없거나 타임프레임 불일치 → 이어달리기로 360개 (초기화)
      // 3. Gap 발생 시 → 이어달리기로 360개 재요청 (Self-Healing)
      // ---
      
      const hasExistingData = CandleManager.hasData('upbit', symbol, safeUnit);
      const existingCount = CandleManager.get('upbit', symbol)?.candles?.length || 0;
      
      // 이미 충분한 데이터가 있으면 증분 업데이트
      if (hasExistingData && existingCount >= MOMENTUM_CANDLE_COUNT) {
        // 증분 업데이트: count=3
        const url = 'https://api.upbit.com/v1/candles/minutes/' + safeUnit + '?market=KRW-' + symbol + '&count=' + INCREMENTAL_COUNT;
        const response = await UpbitApiScheduler.request(url);
        
        if (response.data && Array.isArray(response.data) && response.data.length > 0) {
          const result = CandleManager.update('upbit', symbol, safeUnit, response.data);
          if (result !== null) {
            incrementalCount++;
            continue;
          }
        }
      }
      
      // 초기화 모드: 이어달리기로 360개 확보
      // 1차 요청: 최신 200개
      const url1 = 'https://api.upbit.com/v1/candles/minutes/' + safeUnit + '?market=KRW-' + symbol + '&count=200';
      const response1 = await UpbitApiScheduler.request(url1);
      
      if (!response1.data || !Array.isArray(response1.data) || response1.data.length === 0) {
        skipCount++;
        continue;
      }
      
      let allCandles = [...response1.data];
      
      // 2차 요청: 1차의 마지막 캔들 이전 데이터 160개 추가
      if (response1.data.length >= 200) {
        const oldestCandle = response1.data[response1.data.length - 1];
        const toParam = oldestCandle.candle_date_time_utc;
        
        const url2 = 'https://api.upbit.com/v1/candles/minutes/' + safeUnit + '?market=KRW-' + symbol + '&count=160&to=' + toParam;
        const response2 = await UpbitApiScheduler.request(url2);
        
        if (response2.data && Array.isArray(response2.data) && response2.data.length > 0) {
          // 병합 (중복 제거)
          const existingTimestamps = new Set(allCandles.map(c => c.timestamp));
          const uniqueCandles = response2.data.filter(c => !existingTimestamps.has(c.timestamp));
          allCandles = [...allCandles, ...uniqueCandles];
        }
      }
      
      // CandleManager에 저장
      CandleManager.initialize('upbit', symbol, safeUnit, allCandles);
      
      //  360개 이상 확보 시 backfilled 플래그 설정
      if (CandleManager.store.upbit && CandleManager.store.upbit[symbol]) {
        CandleManager.store.upbit[symbol].backfilled = true;
      }
      
      fullFetchCount++;
      
    } catch (err) {
      // 스케줄러가 429를 처리하므로 여기서는 스킵만
      skipCount++;
    }
  }
  
  // 파일에 캐시 저장
  CandleManager.saveToFile();
  
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log('[OK]  업비트 Smart Fetch 완료 (' + elapsed + '초)');
  console.log('   [IN] 증분(count=3): ' + incrementalCount + '개');
  console.log('   [PKG] 이어달리기(200+160): ' + fullFetchCount + '개');
  console.log('   ⏭️  스킵: ' + skipCount + '개');
}

// ---
//  캐시에서 업비트 모멘텀 동기식 계산 (aggregateCandles 적용)
// - 1분봉 데이터를 지정 타임프레임으로 합성 후 계산
// - 360개 캔들 기준 High/Low Break 계산
// ---
//  데이터 부족 시 null 반환하도록 수정
//  backfilled 플래그로 수집 중 vs 완료 구분
function calculateUpbitMomentumFromCacheSync(symbol, unit) {
  // ---
  //  backfilled 플래그 확인
  // - backfilled = false/undefined: 수집 중 → "Calc..."
  // - backfilled = true: 수집 완료 → 부족하면 "-"
  // ---
  const isBackfilled = CandleManager.isBackfilled('upbit', symbol, unit);
  
  //  1. Multi-TF Store에서 해당 타임프레임 데이터 우선 확인
  const multiTfData = CandleManager.getMultiTfCandles('upbit', symbol, unit);
  if (multiTfData && multiTfData.length >= MIN_CANDLES_FOR_MOMENTUM) {
    // Multi-TF 데이터로 모멘텀 계산
    const completedCandles = multiTfData.slice(1);  // 현재 형성 중인 캔들 제외
    if (completedCandles.length >= MIN_CANDLES_FOR_MOMENTUM - 1) {
      const useCandles = completedCandles.slice(0, Math.min(MOMENTUM_CANDLE_COUNT, completedCandles.length));
      const n = useCandles.length - 1;
      
      let highBreaks = 0, lowBreaks = 0;
      for (let i = 0; i < n; i++) {
        // Multi-TF는 high/low 필드 사용 (통일된 형식)
        const highField = useCandles[i].high_price || useCandles[i].high;
        const lowField = useCandles[i].low_price || useCandles[i].low;
        const nextHighField = useCandles[i + 1].high_price || useCandles[i + 1].high;
        const nextLowField = useCandles[i + 1].low_price || useCandles[i + 1].low;
        
        if (highField > nextHighField) highBreaks++;
        if (lowField < nextLowField) lowBreaks++;
      }
      
      return { up: Math.round((highBreaks / n) * 100), down: Math.round((lowBreaks / n) * 100), source: 'multiTf' };
    }
  }
  
  //  Multi-TF 데이터 부족 시 backfilled 상태에 따라 분기
  // - 아직 수집 중이면 undefined ("Calc...")
  // - 수집 완료인데 부족하면 null ("-")
  if (!multiTfData || multiTfData.length < MIN_CANDLES_FOR_MOMENTUM) {
    if (!isBackfilled) {
      return { up: undefined, down: undefined, reason: 'backfill_in_progress' };
    }
    // backfilled=true인데 데이터 부족 → Fallback으로 진행
  }
  
  //  2. Fallback: 기존 CandleManager.store 데이터 사용
  const cached = CandleManager.get('upbit', symbol);
  
  //  캐시 자체가 없으면 undefined (아직 로딩 전)
  if (!cached) {
    return { up: isBackfilled ? null : undefined, down: isBackfilled ? null : undefined, reason: 'no_cache' };
  }
  
  //  캐시는 있지만 candles 배열이 없거나 비어있으면
  if (!cached.candles || cached.candles.length === 0) {
    return { up: isBackfilled ? null : undefined, down: isBackfilled ? null : undefined, reason: 'empty_candles' };
  }
  
  //  이하 데이터 부족 케이스도 backfilled 상태에 따라 분기
  if (cached.candles.length < 2) {
    return { up: isBackfilled ? null : undefined, down: isBackfilled ? null : undefined, reason: 'insufficient_candles' };
  }
  
  // 업비트는 이미 타임프레임에 맞게 캔들을 요청하므로
  // aggregateCandles는 글로벌 거래소에서만 사용
  const candles = cached.candles;
  const completedCandles = candles.slice(1);  // 현재 형성 중인 캔들 제외
  
  if (completedCandles.length < 2) {
    return { up: isBackfilled ? null : undefined, down: isBackfilled ? null : undefined, reason: 'insufficient_completed' };
  }
  
  //  360개 캔들 기준으로 계산
  const useCandles = completedCandles.slice(0, Math.min(MOMENTUM_CANDLE_COUNT, completedCandles.length));
  const n = useCandles.length - 1;
  
  //  최소 표본 수 검사 - backfilled 상태에 따라 분기
  if (n < MIN_CANDLES_FOR_MOMENTUM - 1) {
    return { up: isBackfilled ? null : undefined, down: isBackfilled ? null : undefined, reason: 'insufficient_samples' };
  }
  
  let highBreaks = 0, lowBreaks = 0;
  
  for (let i = 0; i < n; i++) {
    if (useCandles[i].high_price > useCandles[i + 1].high_price) highBreaks++;
    if (useCandles[i].low_price < useCandles[i + 1].low_price) lowBreaks++;
  }
  
  return { up: Math.round((highBreaks / n) * 100), down: Math.round((lowBreaks / n) * 100), source: 'store' };
}

// ---
//  서버 시작 시 캐시 파일에서 즉시 모멘텀 계산 (CandleManager 사용)
// ---
function calculateAllMomentumFromCacheSync() {
  console.log('[FAST]  CandleManager에서 모멘텀 즉시 계산 시작...');
  let upbitCount = 0;
  let bithumbCount = 0;
  
  // 업비트 모멘텀 계산 (CandleManager.store.upbit 순회)
  const upbitStore = CandleManager.store.upbit || {};
  Object.keys(upbitStore).forEach(symbol => {
    const cached = upbitStore[symbol];
    if (cached && cached.candles) {
      const momentum = calculateUpbitMomentumFromCacheSync(symbol, momentumTimeframe);
      upbitMomentumCache.set(symbol, momentum);
      
      // coinData에도 반영
      coinData.forEach(coin => {
        if (coin.symbol === symbol && coin.exchange === 'UPBIT_SPOT') {
          coin.upProbability = momentum.up;
          coin.downProbability = momentum.down;
        }
      });
      upbitCount++;
    }
  });
  
  //  빗썸 모멘텀은 기존 캐시에서 계산 (동기식) - 최소 표본 수 검사 추가
  bithumbCandleCache.forEach((candles, symbol) => {
    if (candles && candles.length >= 2) {
      const completedCandles = candles.slice(0, -1);
      if (completedCandles.length >= 2) {
        //  360개 캔들 기준으로 계산
        const useCandles = completedCandles.slice(-Math.min(MOMENTUM_CANDLE_COUNT, completedCandles.length));
        const n = useCandles.length - 1;
        
        //  최소 표본 수 검사 - 미달 시 null
        if (n < MIN_CANDLES_FOR_MOMENTUM - 1) {
          const momentum = { up: null, down: null };
          bithumbMomentumCache.set(symbol, momentum);
          
          coinData.forEach(coin => {
            if (coin.symbol === symbol && coin.exchange === 'BITHUMB_SPOT') {
              coin.upProbability = null;
              coin.downProbability = null;
            }
          });
          return;  // 다음 심볼로
        }
        
        let highBreaks = 0, lowBreaks = 0;
        
        for (let i = useCandles.length - 1; i > 0; i--) {
          if (useCandles[i].high > useCandles[i - 1].high) highBreaks++;
          if (useCandles[i].low < useCandles[i - 1].low) lowBreaks++;
        }
        
        const momentum = { 
          up: Math.round((highBreaks / n) * 100), 
          down: Math.round((lowBreaks / n) * 100) 
        };
        bithumbMomentumCache.set(symbol, momentum);
        
        // coinData에도 반영
        coinData.forEach(coin => {
          if (coin.symbol === symbol && coin.exchange === 'BITHUMB_SPOT') {
            coin.upProbability = momentum.up;
            coin.downProbability = momentum.down;
          }
        });
        bithumbCount++;
      }
    }
  });
  
  console.log('[FAST]  CandleManager에서 모멘텀 즉시 계산 완료 (업비트: ' + upbitCount + '개, 빗썸: ' + bithumbCount + '개)');
}

// ---
//  단일 심볼 모멘텀 재계산 (틱 기반 캔들 완성 시 호출)
// - API 호출 없이 메모리의 캔들만 사용
// ---
function recalcMomentumForSymbol(exchange, symbol) {
  try {
    if (exchange === 'upbit') {
      const momentum = calculateUpbitMomentumFromCacheSync(symbol, momentumTimeframe);
      upbitMomentumCache.set(symbol, momentum);
      
      // coinData에도 반영
      coinData.forEach(coin => {
        if (coin.symbol === symbol && coin.exchange === 'UPBIT_SPOT') {
          coin.upProbability = momentum.up;
          coin.downProbability = momentum.down;
        }
      });
      
      // console.log('[SYNC]  모멘텀 재계산: ' + symbol + ' (up:' + momentum.up + '%, down:' + momentum.down + '%)');
    }
    // 빗썸도 필요시 여기에 추가
  } catch (err) {
    // 조용히 무시 (틱 처리 성능 유지)
  }
}

// ---
// 업비트 모멘텀 계산
// - UpbitApiScheduler 사용 (429 에러 근본 해결)
// ---
// ---
//  업비트 모멘텀 계산 - Smart Fetch 적용
// - CandleManager에 데이터 있으면 캐시 사용 + 증분 업데이트
// - 데이터 없으면 count=200으로 초기화
// ---
//  데이터 부족 시 null 반환하도록 수정
//  backfilled 플래그로 수집 중 vs 완료 구분
//  메모리 최적화 - slice() 제거 → 인덱스 범위 직접 접근
async function calculateUpbitMomentum(symbol, unit) {
  try {
    const safeUnit = isValidTimeframe(unit) ? unit : 1;
    
    // ---
    //  1. Multi-TF Store에서 해당 타임프레임 데이터 우선 확인
    // - 충분한 데이터가 있으면 API 호출 없이 바로 계산
    // ---
    const multiTfCandles = CandleManager.getMultiTfCandles('upbit', symbol, safeUnit);
    if (multiTfCandles && multiTfCandles.length >= MIN_CANDLES_FOR_MOMENTUM) {
      //  slice 제거 → 인덱스 범위 사용
      // 현재 형성 중인 캔들 제외: [1]부터 시작 (최신순이므로 [0]이 현재 형성 중)
      const completedLen = multiTfCandles.length - 1;
      if (completedLen >= MIN_CANDLES_FOR_MOMENTUM - 1) {
        const useLen = Math.min(MOMENTUM_CANDLE_COUNT, completedLen);
        const n = useLen - 1;
        
        let highBreaks = 0, lowBreaks = 0;
        //  multiTfCandles[1] ~ [useLen] 범위 직접 접근
        for (let i = 1; i <= n; i++) {
          const curr = multiTfCandles[i];
          const next = multiTfCandles[i + 1];
          const highField = curr.high_price || curr.high;
          const lowField = curr.low_price || curr.low;
          const nextHighField = next.high_price || next.high;
          const nextLowField = next.low_price || next.low;
          
          if (highField > nextHighField) highBreaks++;
          if (lowField < nextLowField) lowBreaks++;
        }
        
        return { up: Math.round((highBreaks / n) * 100), down: Math.round((lowBreaks / n) * 100), source: 'multiTf' };
      }
    }
    
    // ---
    //  2. Fallback: 기존 API 호출 로직
    // ---
    
    // [Smart Fetch] 메모리에 데이터가 있는지 확인
    const hasExistingData = CandleManager.hasData('upbit', symbol, safeUnit);
    const requestCount = hasExistingData ? INCREMENTAL_COUNT : MAX_CANDLES;
    
    // API 요청 (증분 또는 전체)
    const url = 'https://api.upbit.com/v1/candles/minutes/' + safeUnit + '?market=KRW-' + symbol + '&count=' + requestCount;
    const response = await UpbitApiScheduler.request(url);
    const newCandles = response.data;
    
    //  API 응답 없으면 undefined (수집 중/오류)
    if (!Array.isArray(newCandles) || newCandles.length < 2) {
      return { up: undefined, down: undefined, reason: 'no_api_response' };
    }
    
    let candles;
    
    if (hasExistingData) {
      // 증분 업데이트
      candles = CandleManager.update('upbit', symbol, safeUnit, newCandles);
      
      if (candles === null) {
        // Gap 발생 → Self-Healing
        console.log('[FIX] [calculateUpbitMomentum] ' + symbol + ' Gap 감지 → 전체 재요청');
        const fullUrl = 'https://api.upbit.com/v1/candles/minutes/' + safeUnit + '?market=KRW-' + symbol + '&count=200';
        const fullResponse = await UpbitApiScheduler.request(fullUrl);
        
        if (fullResponse.data && Array.isArray(fullResponse.data) && fullResponse.data.length > 0) {
          candles = CandleManager.initialize('upbit', symbol, safeUnit, fullResponse.data);
        } else {
          return { up: undefined, down: undefined, reason: 'gap_recovery_failed' };
        }
      }
    } else {
      // 초기화 모드
      candles = CandleManager.initialize('upbit', symbol, safeUnit, newCandles);
    }
    
    //  backfilled 플래그 확인
    const isBackfilled = CandleManager.isBackfilled('upbit', symbol, safeUnit);
    const insufficientValue = isBackfilled ? null : undefined;
    
    if (!candles || candles.length < 2) {
      return { up: insufficientValue, down: insufficientValue, backfilled: isBackfilled, reason: 'insufficient_candles' };
    }
    
    //  slice 제거 → 인덱스 범위 사용
    // candles는 최신순, [0]이 현재 형성 중 → [1]부터 완성된 캔들
    const completedLen = candles.length - 1;
    if (completedLen < 2) {
      return { up: insufficientValue, down: insufficientValue, backfilled: isBackfilled, reason: 'insufficient_completed' };
    }
    
    const useLen = Math.min(MOMENTUM_CANDLE_COUNT, completedLen);
    const n = useLen - 1;
    
    //  최소 표본 수 검사 - backfilled 여부에 따라 분기
    if (n < MIN_CANDLES_FOR_MOMENTUM - 1) {
      return { up: insufficientValue, down: insufficientValue, backfilled: isBackfilled, reason: 'insufficient_samples' };
    }
    
    let highBreaks = 0, lowBreaks = 0;
    
    //  candles[1] ~ [useLen] 범위 직접 접근
    for (let i = 1; i <= n; i++) {
      if (candles[i].high_price > candles[i + 1].high_price) highBreaks++;
      if (candles[i].low_price < candles[i + 1].low_price) lowBreaks++;
    }
    
    return { up: Math.round((highBreaks / n) * 100), down: Math.round((lowBreaks / n) * 100), source: 'api' };
  } catch (error) {
    //  오류 발생 시 undefined (재시도 가능성)
    return { up: undefined, down: undefined, error: true };
  }
}

// ---
//  빗썸 모멘텀 계산 - 360개 캔들 기준
// ---
//  데이터 부족 시 null 반환하도록 수정
//  캐시 없음(수집 중) vs 캐시 부족(데이터 부족) 구분
//  메모리 최적화 - slice() 제거 → 인덱스 범위 직접 접근
// - 빗썸 데이터는 과거순(오름차순) 정렬 가정 (오래된 게 앞, 최신이 뒤)
async function calculateBithumbMomentum(symbol, unit) {
  try {
    const isBackfilled = CandleManager.isBackfilled('bithumb', symbol, unit);
    
    //  1. Multi-TF Store에서 해당 타임프레임 데이터 우선 확인
    const multiTfData = CandleManager.getMultiTfCandles('bithumb', symbol, unit);
    if (multiTfData && multiTfData.length >= MIN_CANDLES_FOR_MOMENTUM) {
      //  slice 제거 → 인덱스 범위 사용
      // 빗썸은 과거순이므로 마지막(length-1)이 현재 형성 중
      const totalLen = multiTfData.length;
      const completedLen = totalLen - 1;  // 마지막 제외
      
      if (completedLen >= MIN_CANDLES_FOR_MOMENTUM - 1) {
        const useLen = Math.min(MOMENTUM_CANDLE_COUNT, completedLen);
        const n = useLen - 1;
        
        if (n >= MIN_CANDLES_FOR_MOMENTUM - 1) {
          let highBreaks = 0, lowBreaks = 0;
          //  인덱스 범위 직접 접근
          // 뒤에서부터 useLen개 사용: (completedLen - useLen) ~ (completedLen - 1)
          const startIdx = completedLen - useLen;
          const endIdx = completedLen - 1;
          
          // 역순으로 순회하며 비교 (최신 → 과거)
          for (let i = endIdx; i > startIdx; i--) {
            if (multiTfData[i].high > multiTfData[i - 1].high) highBreaks++;
            if (multiTfData[i].low < multiTfData[i - 1].low) lowBreaks++;
          }
          
          return { up: Math.round((highBreaks / n) * 100), down: Math.round((lowBreaks / n) * 100), cached: true, source: 'multiTf' };
        }
      }
    }
    
    //  Multi-TF 데이터 부족 시 backfilled 상태에 따라 분기
    if (!multiTfData || multiTfData.length < MIN_CANDLES_FOR_MOMENTUM) {
      if (!isBackfilled) {
        return { up: undefined, down: undefined, cached: false, reason: 'backfill_in_progress' };
      }
    }
    
    //  2. Fallback: 기존 API 호출 로직
    let candles = [];
    if (BITHUMB_DIRECT_TIMEFRAMES.includes(unit)) {
      const interval = BITHUMB_INTERVAL_MAP[unit];
      if (interval) candles = await fetchBithumbCandles(symbol, interval);
    } else if (unit === 15) {
      const cached5MinCandles = bithumbCandleCache.get(symbol);
      if (!cached5MinCandles) {
        return { up: isBackfilled ? null : undefined, down: isBackfilled ? null : undefined, cached: false, reason: 'no_cache' };
      }
      if (cached5MinCandles.length < MIN_CANDLES_FOR_MOMENTUM * 3) {
        return { up: isBackfilled ? null : undefined, down: isBackfilled ? null : undefined, cached: false, reason: 'insufficient_5min_cache' };
      }
      candles = aggregateBithumb5MinCandles(cached5MinCandles, 15);
    } else if (unit === 240) {
      const cached1HourCandles = bithumb1HourCache.get(symbol);
      if (!cached1HourCandles) {
        return { up: isBackfilled ? null : undefined, down: isBackfilled ? null : undefined, cached: false, reason: 'no_1hour_cache' };
      }
      if (cached1HourCandles.length < MIN_CANDLES_FOR_MOMENTUM * 4) {
        return { up: isBackfilled ? null : undefined, down: isBackfilled ? null : undefined, cached: false, reason: 'insufficient_1hour_cache' };
      }
      candles = aggregateBithumbCandles(cached1HourCandles, 60, 240);
    } else {
      return { up: isBackfilled ? null : undefined, down: isBackfilled ? null : undefined };
    }
    
    if (!candles) return { up: isBackfilled ? null : undefined, down: isBackfilled ? null : undefined, reason: 'no_candles' };
    if (candles.length < 2) return { up: isBackfilled ? null : undefined, down: isBackfilled ? null : undefined, reason: 'insufficient_candles' };
    
    //  Fallback도 인덱스 범위 사용
    // candles는 과거순이므로 마지막이 현재 형성 중
    const totalLen = candles.length;
    const completedLen = totalLen - 1;
    if (completedLen < 2) return { up: isBackfilled ? null : undefined, down: isBackfilled ? null : undefined, reason: 'insufficient_completed' };
    
    const useLen = Math.min(MOMENTUM_CANDLE_COUNT, completedLen);
    const n = useLen - 1;
    
    if (n < MIN_CANDLES_FOR_MOMENTUM - 1) return { up: isBackfilled ? null : undefined, down: isBackfilled ? null : undefined, reason: 'insufficient_samples' };
    
    let highBreaks = 0, lowBreaks = 0;
    const startIdx = completedLen - useLen;
    const endIdx = completedLen - 1;
    
    for (let i = endIdx; i > startIdx; i--) {
      if (candles[i].high > candles[i - 1].high) highBreaks++;
      if (candles[i].low < candles[i - 1].low) lowBreaks++;
    }
    
    return { up: Math.round((highBreaks / n) * 100), down: Math.round((lowBreaks / n) * 100), cached: (unit === 15 || unit === 240), source: 'api' };
  } catch (error) {
    console.error('[ERROR] 빗썸 모멘텀 계산 오류 (' + symbol + '):', error.message);
    return { up: undefined, down: undefined, error: true };
  }
}

// ---
//  글로벌 거래소 모멘텀 계산 (캔들 슬라이싱 최적화)
// -  캔들 합성 전 필요한 분량만 slice하여 CPU 부하 감소
// - 1분봉 데이터를 momentumTimeframe으로 합성 후 계산
// - 합성된 캔들 360개 기준 High/Low Break 계산
// - 3분봉 ≠ 5분봉 모멘텀 보장 (서로 다른 값 반환)
// ---
//  timeframeOverride 인자 추가 (전역 변수 의존성 제거)
//  최소 표본 수(MIN_REQUIRED_SAMPLES) 미만 시 up/down: null 반환
//  캐시 없음 → undefined, 캐시 있음 + 데이터 부족 → null (단순화)
//  메모리 최적화 - slice() 제거 → 인덱스 범위 직접 접근
// - 글로벌 데이터는 최신순(내림차순) 정렬 (최신이 앞, 오래된 게 뒤)
function calculateGlobalMomentum(exchange, symbol, timeframeOverride) {
  const tf = timeframeOverride || momentumTimeframe;
  const storeKey = exchange.toLowerCase().replace('_', '_');
  
  //  Multi-TF 캔들 우선 사용
  const multiTfCandles = CandleManager.getMultiTfCandles(storeKey, symbol, tf);
  
  if (multiTfCandles && multiTfCandles.length >= MIN_CANDLES_FOR_MOMENTUM) {
    //  slice 제거 → 인덱스 범위 사용
    // 최신순이므로 [0]이 현재 형성 중 → [1]부터 완성된 캔들
    const completedLen = multiTfCandles.length - 1;
    
    if (completedLen < 2) {
      return { up: null, down: null, candleCount: multiTfCandles.length, aggregatedCount: 0, source: 'multi_tf', insufficient: true };
    }
    
    const useLen = Math.min(MOMENTUM_CANDLE_COUNT, completedLen);
    const n = useLen - 1;
    
    if (n < MIN_CANDLES_FOR_MOMENTUM - 1) {
      return { up: null, down: null, candleCount: multiTfCandles.length, aggregatedCount: useLen, n: n, source: 'multi_tf', insufficient: true };
    }
    
    let highBreaks = 0, lowBreaks = 0;
    
    //  multiTfCandles[1] ~ [useLen] 범위 직접 접근
    for (let i = 1; i <= n; i++) {
      const current = multiTfCandles[i];
      const prev = multiTfCandles[i + 1];
      
      if (current.high_price > prev.high_price) highBreaks++;
      if (current.low_price < prev.low_price) lowBreaks++;
    }
    
    return {
      up: Math.round((highBreaks / n) * 100),
      down: Math.round((lowBreaks / n) * 100),
      candleCount: multiTfCandles.length,
      aggregatedCount: useLen,
      n: n,
      source: 'multi_tf'
    };
  }
  
  // ---
  // [Fallback] 기존 방식: 1분봉 합성
  // - multiTfStore에 캔들이 없거나 부족할 때 사용
  // ---
  const data = CandleManager.store[storeKey]?.[symbol];
  
  if (!data) {
    return { up: undefined, down: undefined, candleCount: 0, aggregatedCount: 0, source: 'none', reason: 'no_data' };
  }
  
  if (!data.candles || data.candles.length === 0) {
    return { up: undefined, down: undefined, candleCount: 0, aggregatedCount: 0, source: 'none', reason: 'empty_candles' };
  }
  
  if (data.candles.length < 10) {
    return { up: null, down: null, candleCount: data.candles.length, aggregatedCount: 0, source: 'none', insufficient: true };
  }
  
  //  캔들 슬라이싱 - aggregateCandles에 전달할 범위 제한용
  // 이 slice는 유지 - 원본 전체(43,200개)를 넘기면 더 많은 메모리 사용
  const rawCandlesAll = data.candles;
  const sliceCount = Math.min(
    rawCandlesAll.length,
    tf * CANDLE_SLICE_MULTIPLIER
  );
  
  const rawCandles = rawCandlesAll.slice(0, sliceCount);
  const aggregatedCandles = aggregateCandles(rawCandles, tf);
  
  //  합성 결과에 대해서도 인덱스 범위 사용
  // 최신순이므로 [0]이 현재 형성 중
  const completedLen = aggregatedCandles.length - 1;
  
  if (completedLen < 2) {
    return { up: null, down: null, candleCount: rawCandles.length, aggregatedCount: completedLen, source: 'aggregated', insufficient: true };
  }
  
  const useLen = Math.min(MOMENTUM_CANDLE_COUNT, completedLen);
  const n = useLen - 1;
  
  if (n < MIN_CANDLES_FOR_MOMENTUM - 1) {
    return { up: null, down: null, candleCount: rawCandles.length, aggregatedCount: useLen, n: n, source: 'aggregated', insufficient: true };
  }
  
  let highBreaks = 0, lowBreaks = 0;
  
  //  aggregatedCandles[1] ~ [useLen] 범위 직접 접근
  for (let i = 1; i <= n; i++) {
    const current = aggregatedCandles[i];
    const prev = aggregatedCandles[i + 1];
    
    if (current.high_price > prev.high_price) highBreaks++;
    if (current.low_price < prev.low_price) lowBreaks++;
  }
  
  return {
    up: Math.round((highBreaks / n) * 100),
    down: Math.round((lowBreaks / n) * 100),
    candleCount: rawCandles.length,
    aggregatedCount: useLen,
    n: n,
    source: 'aggregated'
  };
}

// ════════════════════════════════════════════════════════════════
//  캐시 데이터 존재 여부 확인
// - 해당 타임프레임에 유효한 모멘텀 데이터가 있는지 체크
// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════
//  충분한 캐시 데이터 여부 확인 (기존 hasCacheDataForTimeframe 대체)
// - 기존: 1개라도 있으면 true → 나머지 코인 영원히 Calc... 버그!
// - 신규: 전체 마켓의 90% 이상 데이터가 있어야 true (볼린저밴드 2σ 참고)
// ════════════════════════════════════════════════════════════════
function hasSufficientCacheData(tf) {
  const THRESHOLD = 0.9;  // 90% 이상이면 충분하다고 판단 (볼린저밴드 2σ ≈ 95% 참고)
  
  let totalMarkets = 0;
  let cachedMarkets = 0;
  
  // 국내 거래소 체크
  if (UPBIT_MARKETS && UPBIT_MARKETS.length > 0) {
    totalMarkets += UPBIT_MARKETS.length;
    const upbitCache = momentumCacheMap.upbit?.[tf];
    if (upbitCache) {
      UPBIT_MARKETS.forEach(symbol => {
        const m = upbitCache.get(symbol);
        if (m && typeof m.up === 'number') cachedMarkets++;
      });
    }
  }
  
  if (BITHUMB_MARKETS && BITHUMB_MARKETS.length > 0) {
    totalMarkets += BITHUMB_MARKETS.length;
    const bithumbCache = momentumCacheMap.bithumb?.[tf];
    if (bithumbCache) {
      BITHUMB_MARKETS.forEach(symbol => {
        const m = bithumbCache.get(symbol);
        if (m && typeof m.up === 'number') cachedMarkets++;
      });
    }
  }
  
  // 글로벌 거래소 체크
  const globalCache = globalMomentumCache[tf];
  if (BINANCE_SPOT_MARKETS && BINANCE_SPOT_MARKETS.length > 0) {
    totalMarkets += BINANCE_SPOT_MARKETS.length;
    if (globalCache) {
      BINANCE_SPOT_MARKETS.forEach(symbol => {
        const m = globalCache.get('BINANCE_SPOT:' + symbol);
        if (m && typeof m.up === 'number') cachedMarkets++;
      });
    }
  }
  
  if (BINANCE_FUTURES_MARKETS && BINANCE_FUTURES_MARKETS.length > 0) {
    totalMarkets += BINANCE_FUTURES_MARKETS.length;
    if (globalCache) {
      BINANCE_FUTURES_MARKETS.forEach(symbol => {
        const m = globalCache.get('BINANCE_FUTURES:' + symbol);
        if (m && typeof m.up === 'number') cachedMarkets++;
      });
    }
  }
  
  if (OKX_SPOT_MARKETS && OKX_SPOT_MARKETS.length > 0) {
    totalMarkets += OKX_SPOT_MARKETS.length;
    if (globalCache) {
      OKX_SPOT_MARKETS.forEach(symbol => {
        const m = globalCache.get('OKX_SPOT:' + symbol);
        if (m && typeof m.up === 'number') cachedMarkets++;
      });
    }
  }
  
  if (OKX_FUTURES_MARKETS && OKX_FUTURES_MARKETS.length > 0) {
    totalMarkets += OKX_FUTURES_MARKETS.length;
    if (globalCache) {
      OKX_FUTURES_MARKETS.forEach(symbol => {
        const m = globalCache.get('OKX_FUTURES:' + symbol);
        if (m && typeof m.up === 'number') cachedMarkets++;
      });
    }
  }
  
  if (totalMarkets === 0) return false;
  
  const ratio = cachedMarkets / totalMarkets;
  console.log('[JIT]  캐시 현황: ' + cachedMarkets + '/' + totalMarkets + ' (' + Math.round(ratio * 100) + '%)');
  
  return ratio >= THRESHOLD;
}

// ════════════════════════════════════════════════════════════════
//  백필이 필요한 심볼 목록 추출
// - 캐시에 없거나 캔들 데이터가 없는 심볼만 반환
// ════════════════════════════════════════════════════════════════
function getMissingSymbols(exchange, tf, marketList) {
  if (!marketList || marketList.length === 0) return [];
  
  const missing = [];
  const multiTfStore = CandleManager.multiTfStore[exchange];
  
  marketList.forEach(symbol => {
    // 캔들 데이터가 없거나 부족하면 missing에 추가
    const tfData = multiTfStore?.[symbol]?.[tf];
    const candleCount = tfData?.candles?.length || 0;
    
    if (candleCount < 10) {  // 최소 10개 필요
      missing.push(symbol);
    }
  });
  
  return missing;
}

//  기존 hasCacheDataForTimeframe도 유지 (하위 호환)
function hasCacheDataForTimeframe(tf) {
  // 국내 거래소 체크
  const upbitCache = momentumCacheMap.upbit?.[tf];
  const bithumbCache = momentumCacheMap.bithumb?.[tf];
  
  // 하나라도 데이터가 있으면 true
  if (upbitCache && upbitCache.size > 0) {
    // 실제 숫자 값이 있는지 확인
    for (const [symbol, m] of upbitCache) {
      if (typeof m.up === 'number') return true;
    }
  }
  
  if (bithumbCache && bithumbCache.size > 0) {
    for (const [symbol, m] of bithumbCache) {
      if (typeof m.up === 'number') return true;
    }
  }
  
  // 글로벌 거래소 체크
  const globalCache = globalMomentumCache[tf];
  if (globalCache && globalCache.size > 0) {
    for (const [key, m] of globalCache) {
      if (typeof m.up === 'number') return true;
    }
  }
  
  return false;
}

// ════════════════════════════════════════════════════════════════
//  JIT 백필 (락 포함)
//  부분 백필 지원 - 캐시에 없는 코인만 백필!
// - 동일 타임프레임에 대해 중복 백필 방지
// - 1000명이 동시에 요청해도 실제 백필은 1번만!
// - 백필 완료 시 해당 TF 모든 클라이언트에게 브로드캐스트
// -  90% 기준 + 3회 재시도 안전장치
// ════════════════════════════════════════════════════════════════
async function jitBackfillWithLock(tf) {
  // ════════════════════════════════════════════════════════════════
  //  안전장치: 3회 실패 시 강제 완료 처리
  // - 상폐 코인, API 장애 등으로 90% 달성 불가 시 무한루프 방지
  // - 부족한 심볼들은 "-"로 표시 (null 설정)
  // ════════════════════════════════════════════════════════════════
  const failCount = jitBackfillFailCount.get(tf) || 0;
  if (failCount >= MAX_BACKFILL_RETRY) {
    console.log('[JIT]  TF ' + tf + '분 ' + MAX_BACKFILL_RETRY + '회 실패 → 강제 완료 처리 (무한루프 방지)');
    
    // ════════════════════════════════════════════════════════════════
    //  부족한 심볼들을 null로 설정 → 프론트엔드에서 "-" 표시
    // - "Calc..." 대신 "-"로 표시하여 UX 개선
    // - 고객: "아, 이건 안 뜨는 값이구나"
    // ════════════════════════════════════════════════════════════════
    const unavailableSet = new Set();
    
    // 각 거래소별 부족한 심볼 수집 및 캐시에 null 설정
    const exchanges = [
      { name: 'upbit', markets: UPBIT_MARKETS, cache: momentumCacheMap.upbit },
      { name: 'bithumb', markets: BITHUMB_MARKETS, cache: momentumCacheMap.bithumb }
    ];
    
    exchanges.forEach(({ name, markets, cache }) => {
      if (!markets || !cache) return;
      const missing = getMissingSymbols(name, tf, markets);
      missing.forEach(symbol => {
        unavailableSet.add(name + ':' + symbol);
        // 캐시에 null 설정 → 프론트엔드에서 "-" 표시
        if (!cache[tf]) cache[tf] = new Map();
        cache[tf].set(symbol, { up: null, down: null });
      });
    });
    
    // 글로벌 거래소
    const globalExchanges = [
      { name: 'binance_spot', markets: BINANCE_SPOT_MARKETS, prefix: 'BINANCE_SPOT' },
      { name: 'binance_futures', markets: BINANCE_FUTURES_MARKETS, prefix: 'BINANCE_FUTURES' },
      { name: 'okx_spot', markets: OKX_SPOT_MARKETS, prefix: 'OKX_SPOT' },
      { name: 'okx_futures', markets: OKX_FUTURES_MARKETS, prefix: 'OKX_FUTURES' }
    ];
    
    globalExchanges.forEach(({ name, markets, prefix }) => {
      if (!markets) return;
      const missing = getMissingSymbols(name, tf, markets);
      missing.forEach(symbol => {
        unavailableSet.add(prefix + ':' + symbol);
        // 글로벌 캐시에 null 설정
        if (!globalMomentumCache[tf]) globalMomentumCache[tf] = new Map();
        globalMomentumCache[tf].set(prefix + ':' + symbol, { up: null, down: null });
      });
    });
    
    unavailableSymbolsPerTf.set(tf, unavailableSet);
    console.log('[JIT]  TF ' + tf + '분 ' + unavailableSet.size + '개 심볼 "-" 처리 완료');
    
    jitBackfillCompleted.add(tf);
    return true;
  }
  
  // 1. 이미 백필 완료된 타임프레임이면 스킵
  if (jitBackfillCompleted.has(tf)) {
    console.log('[JIT]  TF ' + tf + '분 이미 완료됨');
    
    // ════════════════════════════════════════════════════════════════
    //  캐시가 비어있으면 계산만 다시 수행!
    // - 백필 완료했는데 캐시가 없는 상황 대비
    // ════════════════════════════════════════════════════════════════
    if (!hasCacheDataForTimeframe(tf)) {
      console.log('[JIT]  캐시 없음 → 계산 강제 수행!');
      updateGlobalMomentumCaches();
    }
    return true;
  }
  
  // ════════════════════════════════════════════════════════════════
  //  충분한 데이터가 있는지 확인 (90% 기준)
  // - 기존: 1개라도 있으면 스킵 → 버그!
  // - 신규: 90% 이상 있어야 스킵, 그 외에는 부분 백필
  // ════════════════════════════════════════════════════════════════
  if (hasSufficientCacheData(tf)) {
    console.log('[JIT]  TF ' + tf + '분 캐시 충분 (90%+) → 스킵');
    jitBackfillCompleted.add(tf);
    return true;
  }
  
  // 3. 백필이 이미 진행 중이면 기다림
  if (jitBackfillInProgress.has(tf)) {
    console.log('[JIT]  TF ' + tf + '분 백필 진행 중 → 대기...');
    try {
      await jitBackfillInProgress.get(tf);
      return true;
    } catch (err) {
      console.error('[JIT]  대기 중 오류:', err.message);
      return false;
    }
  }
  
  // 4. 백필 시작 (락 걸고!)
  console.log('[JIT]  TF ' + tf + '분 백필 시작! (시도 ' + (failCount + 1) + '/' + MAX_BACKFILL_RETRY + ')');
  const startTime = Date.now();
  
  const backfillPromise = (async () => {
    try {
      // ════════════════════════════════════════════════════════════════
      //  부분 백필 - 캐시에 없는 코인만 백필!
      // - getMissingSymbols()로 부족한 심볼만 추출
      // - 전체 마켓 대신 missing만 처리 → 시간 단축!
      // ════════════════════════════════════════════════════════════════
      const JIT_CHUNK_SIZE = 10;  // 동시 요청 수 (보수적으로)
      const MIN_CANDLES = 360;
      
      // ────────────────────────────────────────
      //  업비트 JIT 백필 (부분 백필 지원!)
      // ────────────────────────────────────────
      const jitBackfillUpbit = async () => {
        if (!UPBIT_MARKETS || UPBIT_MARKETS.length === 0) return;
        
        //  부족한 심볼만 추출
        const missingSymbols = getMissingSymbols('upbit', tf, UPBIT_MARKETS);
        if (missingSymbols.length === 0) {
          console.log('[JIT]  업비트 ' + tf + '분봉 이미 충분');
          return;
        }
        
        console.log('[JIT]  업비트 ' + tf + '분봉 부족: ' + missingSymbols.length + '/' + UPBIT_MARKETS.length + '개');
        const chunks = chunkArray(missingSymbols, JIT_CHUNK_SIZE);
        
        for (const chunk of chunks) {
          await Promise.all(chunk.map(async (symbol) => {
            try {
              const candles = await fetchUpbitCandlesMultiTf(symbol, MIN_CANDLES + 10, tf);
              if (candles && candles.length > 0) {
                CandleManager.initializeMultiTfCandles('upbit', symbol, tf, candles);
                CandleManager.setBackfilled('upbit', symbol, tf, true);
              }
            } catch (err) {
              // 개별 심볼 실패는 무시
            }
          }));
        }
        console.log('[JIT]  업비트 ' + tf + '분봉 완료 (' + missingSymbols.length + '개 백필)');
      };
      
      // ────────────────────────────────────────
      //  빗썸 JIT 백필 (부분 백필 지원!)
      // ────────────────────────────────────────
      const jitBackfillBithumb = async () => {
        if (!BITHUMB_MARKETS || BITHUMB_MARKETS.length === 0) return;
        
        //  부족한 심볼만 추출
        const missingSymbols = getMissingSymbols('bithumb', tf, BITHUMB_MARKETS);
        if (missingSymbols.length === 0) {
          console.log('[JIT]  빗썸 ' + tf + '분봉 이미 충분');
          return;
        }
        
        console.log('[JIT]  빗썸 ' + tf + '분봉 부족: ' + missingSymbols.length + '/' + BITHUMB_MARKETS.length + '개');
        const chunks = chunkArray(missingSymbols, JIT_CHUNK_SIZE);
        
        for (const chunk of chunks) {
          await Promise.all(chunk.map(async (symbol) => {
            try {
              const candles = await fetchBithumbCandlesMultiTf(symbol, MIN_CANDLES + 10, tf);
              if (candles && candles.length > 0) {
                CandleManager.initializeMultiTfCandles('bithumb', symbol, tf, candles);
                CandleManager.setBackfilled('bithumb', symbol, tf, true);
              }
            } catch (err) {
              // 개별 심볼 실패는 무시
            }
          }));
        }
        console.log('[JIT]  빗썸 ' + tf + '분봉 완료 (' + missingSymbols.length + '개 백필)');
      };
      
      // ────────────────────────────────────────
      //  바이낸스 현물 JIT 백필 (부분 백필 지원!)
      // ────────────────────────────────────────
      const jitBackfillBinanceSpot = async () => {
        if (!BINANCE_SPOT_MARKETS || BINANCE_SPOT_MARKETS.length === 0) return;
        
        //  부족한 심볼만 추출
        const missingSymbols = getMissingSymbols('binance_spot', tf, BINANCE_SPOT_MARKETS);
        if (missingSymbols.length === 0) {
          console.log('[JIT]  바이낸스현물 ' + tf + '분봉 이미 충분');
          return;
        }
        
        console.log('[JIT]  바이낸스현물 ' + tf + '분봉 부족: ' + missingSymbols.length + '/' + BINANCE_SPOT_MARKETS.length + '개');
        const chunks = chunkArray(missingSymbols, JIT_CHUNK_SIZE);
        
        for (const chunk of chunks) {
          await Promise.all(chunk.map(async (symbol) => {
            try {
              const candles = await fetchBinanceSpotCandles(symbol, MIN_CANDLES + 10, tf);
              if (candles && candles.length > 0) {
                CandleManager.initializeMultiTfCandles('binance_spot', symbol, tf, candles);
                CandleManager.setBackfilled('binance_spot', symbol, tf, true);
              }
            } catch (err) {
              // 개별 심볼 실패는 무시
            }
          }));
        }
        console.log('[JIT]  바이낸스현물 ' + tf + '분봉 완료 (' + missingSymbols.length + '개 백필)');
      };
      
      // ────────────────────────────────────────
      //  바이낸스 선물 JIT 백필 (부분 백필 지원!)
      // ────────────────────────────────────────
      const jitBackfillBinanceFutures = async () => {
        if (!BINANCE_FUTURES_MARKETS || BINANCE_FUTURES_MARKETS.length === 0) return;
        
        //  부족한 심볼만 추출
        const missingSymbols = getMissingSymbols('binance_futures', tf, BINANCE_FUTURES_MARKETS);
        if (missingSymbols.length === 0) {
          console.log('[JIT]  바이낸스선물 ' + tf + '분봉 이미 충분');
          return;
        }
        
        console.log('[JIT]  바이낸스선물 ' + tf + '분봉 부족: ' + missingSymbols.length + '/' + BINANCE_FUTURES_MARKETS.length + '개');
        const chunks = chunkArray(missingSymbols, JIT_CHUNK_SIZE);
        
        for (const chunk of chunks) {
          await Promise.all(chunk.map(async (symbol) => {
            try {
              const candles = await fetchBinanceFuturesCandles(symbol, MIN_CANDLES + 10, tf);
              if (candles && candles.length > 0) {
                CandleManager.initializeMultiTfCandles('binance_futures', symbol, tf, candles);
                CandleManager.setBackfilled('binance_futures', symbol, tf, true);
              }
            } catch (err) {
              // 개별 심볼 실패는 무시
            }
          }));
        }
        console.log('[JIT]  바이낸스선물 ' + tf + '분봉 완료 (' + missingSymbols.length + '개 백필)');
      };
      
      // ────────────────────────────────────────
      //  OKX 현물 JIT 백필 (부분 백필 지원!)
      // ────────────────────────────────────────
      const jitBackfillOkxSpot = async () => {
        if (!OKX_SPOT_MARKETS || OKX_SPOT_MARKETS.length === 0) return;
        
        //  부족한 심볼만 추출
        const missingSymbols = getMissingSymbols('okx_spot', tf, OKX_SPOT_MARKETS);
        if (missingSymbols.length === 0) {
          console.log('[JIT]  OKX현물 ' + tf + '분봉 이미 충분');
          return;
        }
        
        console.log('[JIT]  OKX현물 ' + tf + '분봉 부족: ' + missingSymbols.length + '/' + OKX_SPOT_MARKETS.length + '개');
        const chunks = chunkArray(missingSymbols, JIT_CHUNK_SIZE);
        
        for (const chunk of chunks) {
          await Promise.all(chunk.map(async (symbol) => {
            try {
              const candles = await fetchOkxSpotCandles(symbol, MIN_CANDLES + 10, null, tf);
              if (candles && candles.length > 0) {
                CandleManager.initializeMultiTfCandles('okx_spot', symbol, tf, candles);
                CandleManager.setBackfilled('okx_spot', symbol, tf, true);
              }
            } catch (err) {
              // 개별 심볼 실패는 무시
            }
          }));
        }
        console.log('[JIT]  OKX현물 ' + tf + '분봉 완료 (' + missingSymbols.length + '개 백필)');
      };
      
      // ────────────────────────────────────────
      //  OKX 선물 JIT 백필 (부분 백필 지원!)
      // ────────────────────────────────────────
      const jitBackfillOkxFutures = async () => {
        if (!OKX_FUTURES_MARKETS || OKX_FUTURES_MARKETS.length === 0) return;
        
        //  부족한 심볼만 추출
        const missingSymbols = getMissingSymbols('okx_futures', tf, OKX_FUTURES_MARKETS);
        if (missingSymbols.length === 0) {
          console.log('[JIT]  OKX선물 ' + tf + '분봉 이미 충분');
          return;
        }
        
        console.log('[JIT]  OKX선물 ' + tf + '분봉 부족: ' + missingSymbols.length + '/' + OKX_FUTURES_MARKETS.length + '개');
        const chunks = chunkArray(missingSymbols, JIT_CHUNK_SIZE);
        
        for (const chunk of chunks) {
          await Promise.all(chunk.map(async (symbol) => {
            try {
              const candles = await fetchOkxFuturesCandles(symbol, MIN_CANDLES + 10, null, tf);
              if (candles && candles.length > 0) {
                CandleManager.initializeMultiTfCandles('okx_futures', symbol, tf, candles);
                CandleManager.setBackfilled('okx_futures', symbol, tf, true);
              }
            } catch (err) {
              // 개별 심볼 실패는 무시
            }
          }));
        }
        console.log('[JIT]  OKX선물 ' + tf + '분봉 완료 (' + missingSymbols.length + '개 백필)');
      };
      
      // ────────────────────────────────────────
      // 모든 거래소 병렬 백필 실행
      // ────────────────────────────────────────
      await Promise.all([
        jitBackfillUpbit(),
        jitBackfillBithumb(),
        jitBackfillBinanceSpot(),
        jitBackfillBinanceFutures(),
        jitBackfillOkxSpot(),
        jitBackfillOkxFutures()
      ]);
      
      // 캐시 갱신
      updateGlobalMomentumCaches();
      
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      console.log('[JIT]  TF ' + tf + '분 백필 완료! (' + elapsed + '초)');
      
      // ════════════════════════════════════════════════════════════════
      //  충분한 캐시가 채워졌을 때만 완료 처리!
      // - 90% 이상 채워지면 완료 처리
      // - 그 미만이면 실패 횟수 증가 → 다음에 부분 백필 시도
      // - 3회 실패 시 강제 완료 (무한루프 방지)
      // ════════════════════════════════════════════════════════════════
      if (hasSufficientCacheData(tf)) {
        jitBackfillCompleted.add(tf);
        jitBackfillFailCount.delete(tf);  // 성공 시 실패 횟수 초기화
        console.log('[JIT]  TF ' + tf + '분 캐시 충분 (90%+) → 완료 처리');
      } else {
        // 실패 횟수 증가
        const currentFail = jitBackfillFailCount.get(tf) || 0;
        jitBackfillFailCount.set(tf, currentFail + 1);
        console.log('[JIT]  TF ' + tf + '분 캐시 부족 (<90%) → 실패 ' + (currentFail + 1) + '/' + MAX_BACKFILL_RETRY + ' (다음에 부분 백필)');
      }
      return true;
    } catch (err) {
      console.error('[JIT]  백필 오류:', err.message);
      return false;
    } finally {
      jitBackfillInProgress.delete(tf);
    }
  })();
  
  jitBackfillInProgress.set(tf, backfillPromise);
  return await backfillPromise;
}

// ════════════════════════════════════════════════════════════════
//  특정 타임프레임 클라이언트들에게만 브로드캐스트
// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════
//  브로드캐스트 쓰로틀링 + 메시지 캐싱
// - 같은 TF에 대해 500ms 내 중복 브로드캐스트 방지
// - 같은 TF 클라이언트들에게 동일 메시지 한 번만 생성
// ════════════════════════════════════════════════════════════════
const broadcastThrottleMap = new Map();  // TF -> 마지막 브로드캐스트 시간
const BROADCAST_THROTTLE_MS = 500;  // 500ms 쓰로틀링

function broadcastToTimeframe(tf) {
  if (typeof clients === 'undefined' || clients.size === 0) return;
  
  //  쓰로틀링 체크
  const now = Date.now();
  const lastBroadcast = broadcastThrottleMap.get(tf) || 0;
  if (now - lastBroadcast < BROADCAST_THROTTLE_MS) {
    // console.log('[THROTTLE]  TF ' + tf + '분 브로드캐스트 스킵 (쓰로틀링)');
    return;
  }
  broadcastThrottleMap.set(tf, now);
  
  //  해당 TF 클라이언트 목록 먼저 수집 (Set 순회 중 변경 방지)
  const targetClients = [];
  clients.forEach(ws => {
    if (ws.readyState !== WebSocket.OPEN) return;
    const clientTf = ws.clientTimeframe || DEFAULT_TIMEFRAME;
    if (clientTf === tf) {
      targetClients.push(ws);
    }
  });
  
  if (targetClients.length === 0) return;
  
  //  메시지 한 번만 생성 (1000명이어도 1번)
  const message = buildCoinDataMessage(tf);
  if (!message) return;
  
  const rankingMsg = message.ranking;
  const refreshMsg = message.refresh;
  
  //  미리 생성된 메시지를 모든 클라이언트에게 전송
  let sentCount = 0;
  targetClients.forEach(ws => {
    try {
      ws.send(rankingMsg);
      ws.send(refreshMsg);
      sentCount++;
    } catch (err) {
      // 전송 실패 무시
    }
  });
  
  if (sentCount > 0) {
    console.log('[BROADCAST]  TF ' + tf + '분 → ' + sentCount + '명에게 데이터 전송 (메시지 캐싱)');
  }
}

//  메시지 빌더 - 한 번만 JSON.stringify
function buildCoinDataMessage(timeframe) {
  //  Fallback 타임프레임 순서 정의
  const fallbackOrder = {
    1: [1],
    3: [3, 1],
    5: [5, 3, 1],
    15: [15, 5, 3, 1],
    30: [30, 15, 5, 1],
    60: [60, 30, 15, 1],
    240: [240, 60, 30, 1]
  };
  const tfOrder = fallbackOrder[timeframe] || [timeframe, 1];
  
  // coinData 복사본에 해당 타임프레임 모멘텀 적용
  const coinDataWithMomentum = coinData.map(coin => {
    const newCoin = { ...coin };
    newCoin.upProbability = undefined;
    newCoin.downProbability = undefined;
    
    //  Fallback 적용
    if (coin.exchange === 'UPBIT_SPOT') {
      for (const tf of tfOrder) {
        const cache = momentumCacheMap.upbit?.[tf];
        if (cache && cache.has(coin.symbol)) {
          const m = cache.get(coin.symbol);
          newCoin.upProbability = m.up;
          newCoin.downProbability = m.down;
          break;
        }
      }
    } else if (coin.exchange === 'BITHUMB_SPOT') {
      for (const tf of tfOrder) {
        const cache = momentumCacheMap.bithumb?.[tf];
        if (cache && cache.has(coin.symbol)) {
          const m = cache.get(coin.symbol);
          newCoin.upProbability = m.up;
          newCoin.downProbability = m.down;
          break;
        }
      }
    } else {
      const globalKey = coin.exchange + ':' + coin.symbol;
      for (const tf of tfOrder) {
        const globalM = globalMomentumCache[tf]?.get(globalKey);
        if (globalM && globalM.up !== undefined) {
          newCoin.upProbability = globalM.up;
          newCoin.downProbability = globalM.down;
          break;
        }
      }

      //  백필 지연 시 레거시 캐시(기본 TF) Fallback
      // - 글로벌 거래소 Multi-TF 캐시가 아직 비어 있을 때에도 상승/하락%를 표시
      if (newCoin.upProbability === undefined) {
        const legacyCacheMap = {
          'BINANCE_SPOT': binanceSpotMomentumCache,
          'BINANCE_FUTURES': binanceFuturesMomentumCache,
          'OKX_SPOT': okxSpotMomentumCache,
          'OKX_FUTURES': okxFuturesMomentumCache
        };

        const legacyCache = legacyCacheMap[coin.exchange];
        if (legacyCache && legacyCache.has(coin.symbol)) {
          const legacyMomentum = legacyCache.get(coin.symbol);
          newCoin.upProbability = legacyMomentum.up;
          newCoin.downProbability = legacyMomentum.down;
        }
      }
    }
    
    return newCoin;
  });
  
  // 상승확률순 정렬
  const sortedCoins = coinDataWithMomentum.sort((a, b) => {
    return (b.upProbability || 0) - (a.upProbability || 0);
  });
  
  // ════════════════════════════════════════════════════════════════
  //  순위표(R) 메시지에 timeframe 추가
  // - 형식 변경: ['R', 'UPBIT:BTC', ...] → ['R', timeframe, 'UPBIT:BTC', ...]
  // - 클라이언트가 다른 TF의 R 메시지를 무시할 수 있도록!
  // ════════════════════════════════════════════════════════════════
  const rankingList = ['R', timeframe];  //  timeframe 추가!
  for (let i = 0; i < sortedCoins.length; i++) {
    const c = sortedCoins[i];
    rankingList.push(c.exchange + ':' + c.symbol);
  }
  
  // 상세 데이터(refresh) 메시지
  const refreshData = sortedCoins.map(c => {
    let upVal = 'CALC';
    let downVal = 'CALC';
    
    if (c.upProbability !== undefined) {
      upVal = c.upProbability === null ? '-' : c.upProbability;
    }
    if (c.downProbability !== undefined) {
      downVal = c.downProbability === null ? '-' : c.downProbability;
    }
    
    return [c.exchange, c.symbol, c.price, upVal, downVal, c.change24h];
  });
  
  return {
    ranking: JSON.stringify(rankingList),
    refresh: JSON.stringify({ type: 'refresh', data: refreshData, timeframe: timeframe })
  };
}

//  글로벌 거래소 모멘텀 캐시 갱신 (1분마다)
function updateGlobalMomentumCaches() {
  //  모든 거래소(글로벌 + 국내) 모멘텀 캐시 갱신
  const globalExchanges = ['binance_spot', 'binance_futures', 'okx_spot', 'okx_futures'];
  const domesticExchanges = ['upbit', 'bithumb'];
  
  const globalCacheMap = {
    'binance_spot': binanceSpotMomentumCache,
    'binance_futures': binanceFuturesMomentumCache,
    'okx_spot': okxSpotMomentumCache,
    'okx_futures': okxFuturesMomentumCache
  };
  
  const exchangeDisplayMap = {
    'binance_spot': 'BINANCE_SPOT',
    'binance_futures': 'BINANCE_FUTURES',
    'okx_spot': 'OKX_SPOT',
    'okx_futures': 'OKX_FUTURES'
  };
  
  let totalUpdated = 0;
  const timeframes = [1, 3, 5, 15, 30, 60, 240];
  
  // ═══════════════════════════════════════════════════════════════
  // [PART 1] 글로벌 거래소 (바이낸스, OKX)
  // ═══════════════════════════════════════════════════════════════
  let globalSkipped = 0;  //  방어적 스킵 카운트
  
  timeframes.forEach(tf => {
    globalExchanges.forEach(exchange => {
      const multiTfStore = CandleManager.multiTfStore[exchange];
      if (!multiTfStore) return;
      
      const symbols = Object.keys(multiTfStore);
      const cache = globalCacheMap[exchange];
      const displayExchange = exchangeDisplayMap[exchange];
      
      symbols.forEach(symbol => {
        const tfData = multiTfStore[symbol]?.[tf];
        const candleCount = tfData?.candles?.length || 0;
        
        if (candleCount >= 10) {
          const momentum = calculateGlobalMomentumMultiTf(exchange, symbol, tf);
          
          // ════════════════════════════════════════════════════════════════
          //  절대 보호 - undefined/null은 무조건 저장 안 함!
          // - 기존 방어 로직 문제: oldValGood=false일 때 undefined 저장됨 (팀킬)
          // - 새 로직: "나쁜 값은 절대 입장 금지" (Gemini 분석 채택)
          // ════════════════════════════════════════════════════════════════
          if (momentum.up === undefined || momentum.up === null) {
            // 나쁜 값 → 절대 저장 안 함, 기존 값 유지!
            globalSkipped++;
            return;  // forEach 내부이므로 continue 대신 return
          }
          
          // 여기 도달하면 momentum.up은 숫자 → 안전하게 저장
          const globalKey = displayExchange + ':' + symbol;
          if (!globalMomentumCache[tf]) {
            globalMomentumCache[tf] = new Map();
          }
          
          globalMomentumCache[tf].set(globalKey, momentum);
          
          if (tf === serverDefaultTimeframe) {
            cache.set(symbol, momentum);
          }
          totalUpdated++;
        }
      });
    });
  });
  
  // ═══════════════════════════════════════════════════════════════
  // [PART 2] 국내 거래소 (업비트, 빗썸) - server187 추가!
  // ═══════════════════════════════════════════════════════════════
  let domesticSkipped = 0;  //  방어적 스킵 카운트
  
  timeframes.forEach(tf => {
    domesticExchanges.forEach(exchange => {
      const multiTfStore = CandleManager.multiTfStore[exchange];
      if (!multiTfStore) return;
      
      const symbols = Object.keys(multiTfStore);
      
      symbols.forEach(symbol => {
        const tfData = multiTfStore[symbol]?.[tf];
        const candleCount = tfData?.candles?.length || 0;
        
        if (candleCount >= 10) {
          //  국내 거래소 모멘텀 계산 (캔들 필드명: high, low)
          const momentum = calculateDomesticMomentumMultiTf(exchange, symbol, tf);
          
          // ════════════════════════════════════════════════════════════════
          //  절대 보호 - undefined/null은 무조건 저장 안 함!
          // - 기존 방어 로직 문제: oldValGood=false일 때 undefined 저장됨 (팀킬)
          // - 새 로직: "나쁜 값은 절대 입장 금지" (Gemini 분석 채택)
          // ════════════════════════════════════════════════════════════════
          if (momentum.up === undefined || momentum.up === null) {
            // 나쁜 값 → 절대 저장 안 함, 기존 값 유지!
            domesticSkipped++;
            return;  // forEach 내부이므로 continue 대신 return
          }
          
          // 여기 도달하면 momentum.up은 숫자 → 안전하게 저장
          // momentumCacheMap[exchange][timeframe] 초기화
          if (!momentumCacheMap[exchange]) {
            momentumCacheMap[exchange] = {};
          }
          if (!momentumCacheMap[exchange][tf]) {
            momentumCacheMap[exchange][tf] = new Map();
          }
          
          momentumCacheMap[exchange][tf].set(symbol, momentum);
          
          // 레거시 캐시에도 저장 (기본 타임프레임용)
          if (tf === serverDefaultTimeframe) {
            if (exchange === 'upbit') {
              upbitMomentumCache.set(symbol, momentum);
            } else if (exchange === 'bithumb') {
              bithumbMomentumCache.set(symbol, momentum);
            }
          }
          
          totalUpdated++;
        }
      });
    });
  });
  
  if (totalUpdated > 0 || globalSkipped > 0 || domesticSkipped > 0) {
    console.log('[DATA]  모멘텀 캐시 갱신: ' + totalUpdated + '개 업데이트, ' + (globalSkipped + domesticSkipped) + '개 스킵(나쁜 값 차단)');
  }
  
  // ════════════════════════════════════════════════════════════════
  //  디버깅: 각 TF별 캐시 크기 로그
  // ════════════════════════════════════════════════════════════════
  const cacheStatus = timeframes.map(tf => {
    const upbitSize = momentumCacheMap.upbit[tf] ? momentumCacheMap.upbit[tf].size : 0;
    const bithumbSize = momentumCacheMap.bithumb[tf] ? momentumCacheMap.bithumb[tf].size : 0;
    const globalSize = globalMomentumCache[tf] ? globalMomentumCache[tf].size : 0;
    return tf + '분(' + upbitSize + '/' + bithumbSize + '/' + globalSize + ')';
  }).join(', ');
  console.log('[DEBUG]  캐시 상태: ' + cacheStatus);
}

// ════════════════════════════════════════════════════════════════
//  국내 거래소(업비트/빗썸) Multi-TF 모멘텀 계산
// - 캔들 필드명: high, low (글로벌과 다름!)
// ════════════════════════════════════════════════════════════════
function calculateDomesticMomentumMultiTf(exchange, symbol, timeframe) {
  try {
    const tfData = CandleManager.multiTfStore[exchange]?.[symbol]?.[timeframe];
    if (!tfData || !tfData.candles || tfData.candles.length < 10) {
      return { up: undefined, down: undefined };
    }
    
    const candles = tfData.candles.slice(-360);
    const n = candles.length;
    
    let highBreaks = 0;
    let lowBreaks = 0;
    
    for (let i = 0; i < n - 1; i++) {
      const current = candles[i];
      const next = candles[i + 1];
      
      //  국내 거래소 캔들 필드명 호환성
      // - 업비트: high, low (fetchUpbitCandlesMultiTf에서 변환됨)
      // - 빗썸: high, low (fetchBithumbCandles 원본)
      // - 일부: high_price, low_price (업비트 원본 유지)
      const currentHigh = current.high !== undefined ? current.high : current.high_price;
      const currentLow = current.low !== undefined ? current.low : current.low_price;
      const nextHigh = next.high !== undefined ? next.high : next.high_price;
      const nextLow = next.low !== undefined ? next.low : next.low_price;
      
      if (nextHigh !== undefined && currentHigh !== undefined && nextHigh > currentHigh) {
        highBreaks++;
      }
      if (nextLow !== undefined && currentLow !== undefined && nextLow < currentLow) {
        lowBreaks++;
      }
    }
    
    return {
      up: Math.round((highBreaks / (n - 1)) * 100),
      down: Math.round((lowBreaks / (n - 1)) * 100)
    };
  } catch (err) {
    console.error(' calculateDomesticMomentumMultiTf 오류:', exchange, symbol, timeframe, err.message);
    return { up: undefined, down: undefined };
  }
}

// ════════════════════════════════════════════════════════════════
//  Multi-TF 스토어에서 글로벌 모멘텀 계산
//  메모리 최적화 - slice() 제거 → 인덱스 범위 직접 접근
// ════════════════════════════════════════════════════════════════
function calculateGlobalMomentumMultiTf(exchange, symbol, timeframe) {
  try {
    const tfData = CandleManager.multiTfStore[exchange]?.[symbol]?.[timeframe];
    if (!tfData || !tfData.candles || tfData.candles.length < 10) {
      return { up: undefined, down: undefined };
    }
    
    //  slice 제거 → 인덱스 범위 사용
    // 뒤에서 360개 사용 (과거순이므로 뒤쪽이 최신)
    const candlesArr = tfData.candles;
    const totalLen = candlesArr.length;
    const useLen = Math.min(360, totalLen);
    const startIdx = totalLen - useLen;
    const n = useLen;
    
    let highBreaks = 0;
    let lowBreaks = 0;
    
    //  캔들 필드명 호환성 수정
    for (let i = startIdx; i < totalLen - 1; i++) {
      const current = candlesArr[i];
      const next = candlesArr[i + 1];
      
      const currentHigh = current.high_price !== undefined ? current.high_price : current.high;
      const currentLow = current.low_price !== undefined ? current.low_price : current.low;
      const nextHigh = next.high_price !== undefined ? next.high_price : next.high;
      const nextLow = next.low_price !== undefined ? next.low_price : next.low;
      
      if (nextHigh !== undefined && currentHigh !== undefined && nextHigh > currentHigh) {
        highBreaks++;
      }
      if (nextLow !== undefined && currentLow !== undefined && nextLow < currentLow) {
        lowBreaks++;
      }
    }
    
    return {
      up: Math.round((highBreaks / (n - 1)) * 100),
      down: Math.round((lowBreaks / (n - 1)) * 100)
    };
  } catch (err) {
    console.error(' calculateGlobalMomentumMultiTf 오류:', exchange, symbol, timeframe, err.message);
    return { up: undefined, down: undefined };
  }
}

// ---
//  글로벌 모멘텀 캐시를 coinData에 반영
// - Backfill/파일 로드 후 호출하여 UI에 즉시 반영
// ---
function applyGlobalMomentumToCoinData() {
  const cacheMap = {
    'BINANCE_SPOT': binanceSpotMomentumCache,
    'BINANCE_FUTURES': binanceFuturesMomentumCache,
    'OKX_SPOT': okxSpotMomentumCache,
    'OKX_FUTURES': okxFuturesMomentumCache
  };
  
  let appliedCount = 0;
  
  coinData.forEach(coin => {
    const cache = cacheMap[coin.exchange];
    if (cache) {
      const momentum = cache.get(coin.symbol);
      if (momentum) {
        coin.upProbability = momentum.up;
        coin.downProbability = momentum.down;
        appliedCount++;
      }
    }
  });
  
  if (appliedCount > 0) {
    console.log('[DATA]  글로벌 모멘텀 → coinData 반영: ' + appliedCount + '개 코인');
  }
}

//  1분마다 글로벌 거래소 모멘텀 캐시 갱신 스케줄러
setInterval(() => {
  updateGlobalMomentumCaches();
}, 60 * 1000);  // 1분

// ════════════════════════════════════════════════════════════════
//  캐시 채워지면 즉시 브로드캐스트!
// - Phase 1 완료를 기다리지 않고, 캐시가 채워지는 즉시 클라이언트에게 전송
// - OKX Rate Limit으로 Phase 1이 느려도 업비트/빗썸 먼저 표시 가능
// - 각 TF별로 "최초 브로드캐스트 완료" 플래그로 중복 전송 방지
// ════════════════════════════════════════════════════════════════
const initialBroadcastDone = {};  // { 1: false, 3: false, ... }

setInterval(() => {
  // 아직 브로드캐스트 안 된 타임프레임 체크
  const timeframesToCheck = [1, 3, 5, 15, 30, 60, 240];
  
  timeframesToCheck.forEach(tf => {
    if (!initialBroadcastDone[tf]) {
      // 캐시에 데이터가 있는지 확인
      const upbitSize = momentumCacheMap.upbit[tf] ? momentumCacheMap.upbit[tf].size : 0;
      const bithumbSize = momentumCacheMap.bithumb[tf] ? momentumCacheMap.bithumb[tf].size : 0;
      const globalSize = globalMomentumCache[tf] ? globalMomentumCache[tf].size : 0;
      
      // 업비트 또는 빗썸 중 하나라도 10개 이상 있으면 브로드캐스트
      if (upbitSize >= 10 || bithumbSize >= 10 || globalSize >= 10) {
        broadcastToTimeframe(tf);
        initialBroadcastDone[tf] = true;
        console.log('[INIT]  TF ' + tf + '분 캐시 채워짐 → 브로드캐스트! (upbit=' + upbitSize + ', bithumb=' + bithumbSize + ', global=' + globalSize + ')');
      }
    }
  });
}, 10 * 1000);  // 10초마다 체크

// ---
//  타임프레임별 정각 갱신 체크 (Time-Aligned Update)
// - 15분봉은 0, 15, 30, 45분에만 갱신
// - 30분봉은 0, 30분에만 갱신
// - 60분봉은 정각(0분)에만 갱신
// - 1분봉, 3분봉, 5분봉은 매번 갱신
// ---
// ---
//  Stable Window 체크
// - 매 분 0초~10초 사이에만 갱신 허용
// - 이렇게 하면 15분 10초~14분 50초 사이에는 리스트가 고정됨
// ---
function isStableWindow() {
  const seconds = new Date().getSeconds();
  return seconds < 10;  // 0~10초 사이에만 true
}

//  타임프레임별 정각 갱신 체크
//  Stable Window 통합 - 정시 + 10초 이내만 갱신
function isTimeForUpdate(timeframe) {
  if (timeframe <= 5) return true;  // 1분, 3분, 5분봉은 매번 갱신
  
  const now = new Date();
  const minutes = now.getMinutes();
  const isStable = isStableWindow();  //  0~10초 체크
  
  //  정시 체크 + Stable Window 체크
  // 정시가 아니면 false, 정시여도 10초 지나면 false
  if (timeframe === 10) return minutes % 10 === 0 && isStable;
  if (timeframe === 15) return minutes % 15 === 0 && isStable;
  if (timeframe === 30) return minutes % 30 === 0 && isStable;
  if (timeframe === 60) return minutes === 0 && isStable;
  if (timeframe === 240) return minutes === 0 && now.getHours() % 4 === 0 && isStable;
  
  return true;  // 기본값: 항상 갱신
}

// ---
//  개별 코인 모멘텀 실시간 갱신 (새 캔들 생성 시 호출)
// - 캐시 업데이트 + coinData 반영
// - WebSocket 핸들러에서 isNewCandle일 때 호출
// -  타임프레임 정각 갱신 조건 추가
// ---
function updateCoinMomentum(exchangeId, symbol) {
  //  타임프레임 정각 갱신 체크
  // - 10분 이상 타임프레임은 해당 간격의 배수 시간에만 갱신
  // - Backfill 중(데이터 초기화 안 된 경우)에는 예외로 계속 갱신
  if (momentumTimeframe >= 10) {
    const checkStoreKey = exchangeId.toLowerCase().replace('_', '_');
    const checkCandleCount = CandleManager.store[checkStoreKey]?.[symbol]?.candles?.length || 0;
    const isBackfilling = checkCandleCount < 100;  // 데이터 100개 미만이면 Backfill 중으로 판단
    
    if (!isBackfilling && !isTimeForUpdate(momentumTimeframe)) {
      return;  // 갱신 주기가 아니면 스킵
    }
  }
  
  // 거래소별 캐시 맵
  const cacheMap = {
    'BINANCE_SPOT': binanceSpotMomentumCache,
    'BINANCE_FUTURES': binanceFuturesMomentumCache,
    'OKX_SPOT': okxSpotMomentumCache,
    'OKX_FUTURES': okxFuturesMomentumCache
  };
  
  const cache = cacheMap[exchangeId];
  if (!cache) return;
  
  // 캔들 개수 확인 (최소 10개 이상이어야 계산)
  const storeKey = exchangeId.toLowerCase().replace('_', '_');
  const candleCount = CandleManager.store[storeKey]?.[symbol]?.candles?.length || 0;
  
  if (candleCount < 10) return;
  
  // 모멘텀 계산 (aggregateCandles 포함)
  const momentum = calculateGlobalMomentum(exchangeId, symbol);
  
  // 캐시 업데이트
  cache.set(symbol, momentum);
  
  // coinData에도 반영
  coinData.forEach(coin => {
    if (coin.symbol === symbol && coin.exchange === exchangeId) {
      coin.upProbability = momentum.up;
      coin.downProbability = momentum.down;
    }
  });
}

// ---
// 모든 코인의 모멘텀 일괄 계산 - 동적 마켓 + 다차원 캐시 사용 (명세 1, 2)
// ---
async function updateAllMomentums() {
  // 마켓 로딩 안 됐으면 대기
  if (!marketsLoaded) {
    console.log('⏳ 모멘텀 갱신 대기 중... (마켓 로딩 필요)');
    return;
  }
  
  console.log('[DATA] 모멘텀 전체 갱신 시작... (타임프레임: ' + momentumTimeframe + '분)');
  
  // 업비트와 빗썸의 공통 코인만 처리 (합집합)
  const allSymbols = [...new Set([...UPBIT_MARKETS, ...BITHUMB_MARKETS])];
  console.log('[DATA] 처리할 코인 수: ' + allSymbols.length + '개');
  
  let successCount = 0;
  
  for (const symbol of allSymbols) {
    // 업비트 모멘텀 (해당 거래소에 있는 경우만)
    if (UPBIT_MARKETS.includes(symbol)) {
      const upbitMomentum = await calculateUpbitMomentum(symbol, momentumTimeframe);
      upbitMomentumCache.set(symbol, upbitMomentum);
      // 다차원 캐시에도 저장
      if (momentumCacheMap.upbit[momentumTimeframe]) {
        momentumCacheMap.upbit[momentumTimeframe].set(symbol, upbitMomentum);
      }
    }
    
    // 빗썸 모멘텀 (해당 거래소에 있는 경우만)
    if (BITHUMB_MARKETS.includes(symbol)) {
      const bithumbMomentum = await calculateBithumbMomentum(symbol, momentumTimeframe);
      bithumbMomentumCache.set(symbol, bithumbMomentum);
      // 다차원 캐시에도 저장
      if (momentumCacheMap.bithumb[momentumTimeframe]) {
        momentumCacheMap.bithumb[momentumTimeframe].set(symbol, bithumbMomentum);
      }
    }
    
    // coinData 업데이트
    coinData.forEach(coin => {
      if (coin.symbol === symbol) {
        if (coin.exchange === 'UPBIT_SPOT' && upbitMomentumCache.has(symbol)) {
          const m = upbitMomentumCache.get(symbol);
          coin.upProbability = m.up;
          coin.downProbability = m.down;
        } else if (coin.exchange === 'BITHUMB_SPOT' && bithumbMomentumCache.has(symbol)) {
          const m = bithumbMomentumCache.get(symbol);
          coin.upProbability = m.up;
          coin.downProbability = m.down;
        }
      }
    });
    
    successCount++;
    // 자체 딜레이 제거 - 스케줄러가 타이밍 관리
  }
  console.log('[OK] 모멘텀 전체 갱신 완료! (' + successCount + '개 처리)');
}

// ---
// 업비트 24시간 전 가격 조회 (Trailing 24H 계산용)
// - 동적 마켓 사용 (명세 1: 하드코딩 제거)
// - UpbitApiScheduler 사용 (429 에러 근본 해결)
// ---
async function fetchUpbit24hPrices() {
  try {
    // 마켓 로딩 안 됐으면 대기
    if (!marketsLoaded || UPBIT_MARKETS.length === 0) {
      console.log('⏳ 업비트 24H 가격 조회 대기 중... (마켓 로딩 필요)');
      return;
    }
    
    console.log('[DATA] 업비트 24시간 전 가격 조회 시작... (' + UPBIT_MARKETS.length + '개 코인)');
    
    let successCount = 0;
    let skipCount = 0;
    
    // 스케줄러를 통한 순차 처리 (자체 딜레이 제거)
    for (const symbol of UPBIT_MARKETS) {
      try {
        const url = 'https://api.upbit.com/v1/candles/minutes/60?market=KRW-' + symbol + '&count=25';
        const response = await UpbitApiScheduler.request(url, {
          headers: { 'Accept': 'application/json' }
        });
        
        if (response.data && response.data.length >= 24) {
          const candle24hAgo = response.data[response.data.length - 1];
          upbit24hPriceCache.set(symbol, candle24hAgo.trade_price);
          successCount++;
        }
      } catch (err) {
        // 스케줄러가 429를 처리하므로 여기서는 스킵만
        skipCount++;
      }
    }
    
    // 파일에 캐시 저장 (수정 1)
    saveUpbitPriceCacheToFile();
    
    console.log('[OK] 업비트 24시간 전 가격 캐시 갱신 완료 (성공: ' + successCount + '개, 스킵: ' + skipCount + '개)');
  } catch (error) {
    console.error('[ERROR] 업비트 24시간 전 가격 조회 실패:', error.message);
  }
}

// 업비트 Trailing 24H 등락률 계산
function calculateUpbit24hChange(symbol, currentPrice) {
  const price24hAgo = upbit24hPriceCache.get(symbol);
  if (price24hAgo && price24hAgo > 0 && currentPrice > 0) {
    return ((currentPrice - price24hAgo) / price24hAgo) * 100;
  }
  return 0;  // 캐시에 없으면 0% 반환
}

// ---
// WebSocket 연결 (업비트) - 동적 마켓 사용 (명세 1)
// ---
function connectUpbit() {
  // 마켓 로딩 안 됐으면 대기 후 재시도
  if (!marketsLoaded || UPBIT_MARKETS.length === 0) {
    const delay = WsReconnectManager.getNextDelay('upbit');
    console.log('[WAIT] 업비트 마켓 로딩 대기... (' + delay + 'ms 후 재시도)');
    setTimeout(connectUpbit, delay);
    return;
  }

  const upbitSocket = new WebSocket('wss://api.upbit.com/websocket/v1');

  upbitSocket.on('open', () => {
    WsReconnectManager.resetAttempts('upbit');  // 연결 성공 시 리셋
    console.log('[OK] 업비트 연결 (' + UPBIT_MARKETS.length + '개 코인)');
    // 동적 마켓 리스트 사용
    const coins = UPBIT_MARKETS.map(symbol => 'KRW-' + symbol);
    upbitSocket.send(JSON.stringify([{ ticket: 'test' }, { type: 'ticker', codes: coins }]));
    
    //  Gap Recovery: 재연결 시 데이터 공백 복구
    if (upbitWsReconnecting) {
      console.log('[FIX]  Gap Recovery 시작 (업비트 WebSocket 재연결 감지)');
      upbitWsReconnecting = false;  // 플래그 리셋
      
      // 백그라운드에서 캔들 데이터 복구 (API 1회 호출)
      // 초기화된 코인만 증분 업데이트 (count=3)
      setTimeout(async () => {
        console.log('[SYNC]  Gap Recovery: 캔들 데이터 증분 업데이트 중...');
        await updateUpbitCandleCache();  // 기존 함수 재사용 (증분 업데이트)
        console.log('[OK]  Gap Recovery 완료!');
      }, 3000);  // 연결 안정화 후 실행
    }
  });
  
  upbitSocket.on('message', (data) => {
    try {
      const ticker = JSON.parse(data.toString());
      const symbol = ticker.code.replace('KRW-', '');
      const price = ticker.trade_price;
      const timestamp = ticker.trade_timestamp || Date.now();
      
      //  USDT 틱 수신 시 환율 실시간 업데이트
      if (symbol === 'USDT') {
        ExchangeRateManager.updateFromTick(price);
      }
      
      // ---
      //  24H 등락률 Fallback 로직
      // - 서버 시작 직후 캐시가 없으면 업비트가 주는 값 임시 사용
      // - 캐시 로딩 완료 후 자동으로 Rolling 24H로 전환
      // ---
      // 1. 업비트가 주는 기본 등락률 (0.05 -> 5%)
      const wsChange = (ticker.signed_change_rate || 0) * 100;
      
      // 2. 우리가 원하는 Rolling 24H 계산 시도
      let change24h = calculateUpbit24hChange(symbol, price);
      
      // 3.  캐시 미스(0 반환) 상태라면, 업비트가 준 값을 임시로 사용 (Fallback)
      if (change24h === 0 && !upbit24hPriceCache.has(symbol)) {
        change24h = wsChange;
      }
      
      // 논리 ID 체계 사용: UPBIT_SPOT
      updateCoinPrice('UPBIT_SPOT', symbol, price, change24h);
      
      //  틱 기반 캔들 합성 (Streaming 모드)
      // - 초기화된 코인만 틱으로 캔들 유지
      // - 초기화 안 된 코인은 Booting 단계에서 API로 채워짐
      if (CandleManager.isInitialized('upbit', symbol)) {
        const result = CandleManager.processTick('upbit', symbol, price, timestamp);
        
        // 새 캔들 완성 시 해당 심볼 모멘텀만 재계산
        if (result.recalcNeeded) {
          recalcMomentumForSymbol('upbit', symbol);
        }
      }
    } catch (err) {}
  });
  
  upbitSocket.on('error', (error) => console.error('업비트 오류:', error));
  
  //  Gap Recovery: 재연결 감지
  upbitSocket.on('close', () => {
    upbitWsReconnecting = true;  // 재연결 플래그 설정
    const delay = WsReconnectManager.getNextDelay('upbit');
    console.log('[WARN]  업비트 WebSocket 연결 끊김 → ' + delay + 'ms 후 재연결 (Gap Recovery 대기)');
    setTimeout(connectUpbit, delay);
  });
}

// ---
// WebSocket 연결 (빗썸) - 동적 마켓 사용 (명세 1)
// ---
function connectBithumb() {
  // 마켓 로딩 안 됐으면 대기 후 재시도
  if (!marketsLoaded || BITHUMB_MARKETS.length === 0) {
    const delay = WsReconnectManager.getNextDelay('bithumb');
    console.log('[WAIT] 빗썸 마켓 로딩 대기... (' + delay + 'ms 후 재시도)');
    setTimeout(connectBithumb, delay);
    return;
  }

  const bithumbSocket = new WebSocket('wss://pubwss.bithumb.com/pub/ws');

  bithumbSocket.on('open', () => {
    WsReconnectManager.resetAttempts('bithumb');  // 연결 성공 시 리셋
    console.log('[OK] 빗썸 WebSocket 연결 (' + BITHUMB_MARKETS.length + '개 코인)');
    // 동적 마켓 리스트 사용
    const coins = BITHUMB_MARKETS.map(symbol => symbol + '_KRW');
    bithumbSocket.send(JSON.stringify({ type: 'ticker', symbols: coins, tickTypes: ['24H'] }));
  });
  
  bithumbSocket.on('message', (data) => {
    try {
      const message = JSON.parse(data.toString());
      if (message.type === 'ticker' && message.content) {
        const content = message.content;
        const symbol = content.symbol ? content.symbol.replace('_KRW', '') : null;
        if (symbol && content.closePrice) {
          const price = parseFloat(content.closePrice);
          const change24h = content.chgRate ? parseFloat(content.chgRate) : 0;
          // 논리 ID 체계 사용: BITHUMB_SPOT
          updateCoinPrice('BITHUMB_SPOT', symbol, price, change24h);
        }
      }
    } catch (err) {}
  });
  
  bithumbSocket.on('error', (error) => console.error('빗썸 오류:', error));
  bithumbSocket.on('close', () => {
    const delay = WsReconnectManager.getNextDelay('bithumb');
    console.log('[WARN] 빗썸 WebSocket 연결 끊김 → ' + delay + 'ms 후 재연결');
    setTimeout(connectBithumb, delay);
  });
}

// ---
//  WebSocket 연결 (바이낸스 현물) - 전체 시세 스트림
// - wss://stream.binance.com:9443/ws/!ticker@arr
// - 모든 심볼의 24시간 티커를 한 번에 수신 (효율적!)
// - 수신 후 BINANCE_SPOT_MARKETS에 있는 심볼만 필터링
// ---
let binanceSpotWsReconnecting = false;
let binanceSpotSocket = null;

function connectBinanceSpot() {
  // [2단계] 전체 시세 스트림은 마켓 로딩 없이도 연결 가능
  // 단, 필터링을 위해 마켓 리스트가 있으면 좋음
  
  const wsUrl = 'wss://stream.binance.com:9443/ws/!ticker@arr';
  
  console.log('[LINK] 바이낸스 현물 WebSocket 연결 시도... (전체 시세 스트림)');
  binanceSpotSocket = new WebSocket(wsUrl);
  
  binanceSpotSocket.on('open', () => {
    WsReconnectManager.resetAttempts('binance_spot');  // 연결 성공 시 리셋
    console.log('[OK] 바이낸스 현물 연결 (전체 시세 스트림 !ticker@arr)');
    binanceSpotWsReconnecting = false;
  });
  
  binanceSpotSocket.on('message', (data) => {
    try {
      const tickers = JSON.parse(data.toString());
      
      // !ticker@arr은 배열로 모든 심볼 티커를 전송
      if (Array.isArray(tickers)) {
        tickers.forEach(ticker => {
          const rawSymbol = ticker.s;  // 'BTCUSDT'
          
          // USDT 페어만 처리
          if (!rawSymbol.endsWith('USDT')) return;
          
          //  심볼 정규화 먼저 수행 (마켓 배열과 비교 및 저장용)
          const symbol = rawSymbol.replace(/USDT$/, '');
          
          //  마켓 리스트가 있으면 필터링 (정규화된 심볼로 비교)
          if (BINANCE_SPOT_MARKETS.length > 0 && !BINANCE_SPOT_MARKETS.includes(symbol)) return;
          
          const price = parseFloat(ticker.c);  // 현재가 (USD)
          const change24h = parseFloat(ticker.P);  // 24시간 등락률 (%)
          
          if (isNaN(price) || price <= 0) return;
          
          //  해외 거래소는 USD 가격 그대로 저장 (클라이언트에서 환율 변환)
          updateCoinPrice('BINANCE_SPOT', symbol, price, change24h);
          
          //  틱을 CandleManager에 쌓고, 새 캔들 생성 시 모멘텀 갱신
          const result = CandleManager.updateFromTick('binance_spot', symbol, price, Date.now());
          if (result && result.isNewCandle && result.candleCount >= 10) {
            updateCoinMomentum('BINANCE_SPOT', symbol);
          }
        });
      }
    } catch (err) {
      // 파싱 오류 무시
    }
  });
  
  binanceSpotSocket.on('error', (error) => console.error('바이낸스 현물 오류:', error.message));
  binanceSpotSocket.on('close', () => {
    binanceSpotWsReconnecting = true;
    const delay = WsReconnectManager.getNextDelay('binance_spot');
    console.log('[WARN] 바이낸스 현물 WebSocket 연결 끊김 → ' + delay + 'ms 후 재연결');
    setTimeout(connectBinanceSpot, delay);
  });
}

// ---
//  WebSocket 연결 (바이낸스 선물) - 전체 시세 스트림
// - wss://fstream.binance.com/ws/!ticker@arr
// - USDT-M 무기한 선물 전체 티커 수신
// ---
let binanceFuturesWsReconnecting = false;
let binanceFuturesSocket = null;

function connectBinanceFutures() {
  // [2단계] 전체 시세 스트림은 마켓 로딩 없이도 연결 가능
  
  const wsUrl = 'wss://fstream.binance.com/ws/!ticker@arr';
  
  console.log('[LINK] 바이낸스 선물 WebSocket 연결 시도... (전체 시세 스트림)');
  binanceFuturesSocket = new WebSocket(wsUrl);
  
  binanceFuturesSocket.on('open', () => {
    WsReconnectManager.resetAttempts('binance_futures');  // 연결 성공 시 리셋
    console.log('[OK] 바이낸스 선물 연결 (전체 시세 스트림 !ticker@arr)');
    binanceFuturesWsReconnecting = false;
  });
  
  binanceFuturesSocket.on('message', (data) => {
    try {
      const tickers = JSON.parse(data.toString());
      
      // !ticker@arr은 배열로 모든 심볼 티커를 전송
      if (Array.isArray(tickers)) {
        tickers.forEach(ticker => {
          const rawSymbol = ticker.s;  // 'BTCUSDT'
          
          // USDT 페어만 처리
          if (!rawSymbol.endsWith('USDT')) return;
          
          //  심볼 정규화 먼저 수행 (마켓 배열과 비교 및 저장용)
          const symbol = rawSymbol.replace(/USDT$/, '');
          
          //  마켓 리스트가 있으면 필터링 (정규화된 심볼로 비교)
          if (BINANCE_FUTURES_MARKETS.length > 0 && !BINANCE_FUTURES_MARKETS.includes(symbol)) return;
          
          const price = parseFloat(ticker.c);  // 현재가 (USD)
          const change24h = parseFloat(ticker.P);  // 24시간 등락률 (%)
          
          if (isNaN(price) || price <= 0) return;
          
          //  해외 거래소는 USD 가격 그대로 저장
          updateCoinPrice('BINANCE_FUTURES', symbol, price, change24h);
          
          //  틱을 CandleManager에 쌓고, 새 캔들 생성 시 모멘텀 갱신
          const result = CandleManager.updateFromTick('binance_futures', symbol, price, Date.now());
          if (result && result.isNewCandle && result.candleCount >= 10) {
            updateCoinMomentum('BINANCE_FUTURES', symbol);
          }
        });
      }
    } catch (err) {
      // 파싱 오류 무시
    }
  });
  
  binanceFuturesSocket.on('error', (error) => console.error('바이낸스 선물 오류:', error.message));
  binanceFuturesSocket.on('close', () => {
    binanceFuturesWsReconnecting = true;
    const delay = WsReconnectManager.getNextDelay('binance_futures');
    console.log('[WARN] 바이낸스 선물 WebSocket 연결 끊김 → ' + delay + 'ms 후 재연결');
    setTimeout(connectBinanceFutures, delay);
  });
}

// ---
//  WebSocket 연결 (OKX 현물) - 배치 구독 방식
// - wss://ws.okx.com:8443/ws/v5/public
// - 최대 100개 채널 동시 구독 가능 → 배치로 분할 전송
// ---
let okxSpotWsReconnecting = false;
let okxSpotSocket = null;

function connectOkxSpot() {
  if (!marketsLoaded || OKX_SPOT_MARKETS.length === 0) {
    const delay = WsReconnectManager.getNextDelay('okx_spot');
    console.log('[WAIT] OKX 현물 마켓 로딩 대기... (' + delay + 'ms 후 재시도)');
    setTimeout(connectOkxSpot, delay);
    return;
  }

  console.log('[LINK] OKX 현물 WebSocket 연결 시도... (' + OKX_SPOT_MARKETS.length + '개 페어)');
  okxSpotSocket = new WebSocket('wss://ws.okx.com:8443/ws/v5/public');

  okxSpotSocket.on('open', () => {
    WsReconnectManager.resetAttempts('okx_spot');  // 연결 성공 시 리셋
    console.log('[OK] OKX 현물 연결됨 - 배치 구독 시작...');
    okxSpotWsReconnecting = false;
    
    // [2단계] 배치(Batch) 구독: 100개씩 나누어 전송
    const BATCH_SIZE = 100;
    const batches = [];
    for (let i = 0; i < OKX_SPOT_MARKETS.length; i += BATCH_SIZE) {
      batches.push(OKX_SPOT_MARKETS.slice(i, i + BATCH_SIZE));
    }
    
    console.log('   [PKG] OKX 현물: ' + batches.length + '개 배치로 분할 (' + OKX_SPOT_MARKETS.length + '개 페어)');
    
    // 각 배치를 500ms 간격으로 전송 (Rate Limit 방지)
    batches.forEach((batch, index) => {
      setTimeout(() => {
        if (okxSpotSocket && okxSpotSocket.readyState === WebSocket.OPEN) {
          const subscribeMsg = {
            op: 'subscribe',
            //  마켓 배열에 정규화된 심볼('BTC')이 저장되어 있으므로,
            // OKX API 구독 시에는 '-USDT'를 다시 붙여서 전송
            args: batch.map(symbol => ({
              channel: 'tickers',
              instId: symbol + '-USDT'  // 'BTC' → 'BTC-USDT'
            }))
          };
          okxSpotSocket.send(JSON.stringify(subscribeMsg));
          console.log('   [OK] OKX 현물 배치 ' + (index + 1) + '/' + batches.length + ' 구독 완료 (' + batch.length + '개)');
        }
      }, index * 500);  // 500ms 간격
    });
  });
  
  okxSpotSocket.on('message', (data) => {
    try {
      const message = JSON.parse(data.toString());
      // OKX 응답 형식: { arg: {...}, data: [{...}] }
      if (message.data && Array.isArray(message.data)) {
        message.data.forEach(ticker => {
          const instId = ticker.instId;  // 'BTC-USDT'
          const price = parseFloat(ticker.last);  // 현재가 (USD)
          
          if (isNaN(price) || price <= 0) return;
          
          // 24시간 등락률 계산
          const open24h = parseFloat(ticker.open24h);
          const change24h = open24h > 0 ? ((price - open24h) / open24h * 100) : 0;
          
          //  심볼 표준화: 'BTC-USDT' → 'BTC' (기초 자산만 저장)
          const symbol = instId.replace(/-USDT$/, '');
          
          //  해외 거래소는 USD 가격 그대로 저장
          updateCoinPrice('OKX_SPOT', symbol, price, change24h);
          
          //  틱을 CandleManager에 쌓고, 새 캔들 생성 시 모멘텀 갱신
          const result = CandleManager.updateFromTick('okx_spot', symbol, price, Date.now());
          if (result && result.isNewCandle && result.candleCount >= 10) {
            updateCoinMomentum('OKX_SPOT', symbol);
          }
        });
      }
    } catch (err) {
      // 파싱 오류 무시
    }
  });
  
  okxSpotSocket.on('error', (error) => console.error('OKX 현물 오류:', error.message));
  okxSpotSocket.on('close', () => {
    okxSpotWsReconnecting = true;
    const delay = WsReconnectManager.getNextDelay('okx_spot');
    console.log('[WARN] OKX 현물 WebSocket 연결 끊김 → ' + delay + 'ms 후 재연결');
    setTimeout(connectOkxSpot, delay);
  });
  
  // OKX는 30초마다 ping 필요
  const pingInterval = setInterval(() => {
    if (okxSpotSocket && okxSpotSocket.readyState === WebSocket.OPEN) {
      okxSpotSocket.send('ping');
    } else {
      clearInterval(pingInterval);
    }
  }, 25000);
}

// ---
//  WebSocket 연결 (OKX 선물) - 배치 구독 방식
// - wss://ws.okx.com:8443/ws/v5/public
// - USDT 무기한 스왑 → 배치로 분할 전송
// ---
let okxFuturesWsReconnecting = false;
let okxFuturesSocket = null;

function connectOkxFutures() {
  if (!marketsLoaded || OKX_FUTURES_MARKETS.length === 0) {
    const delay = WsReconnectManager.getNextDelay('okx_futures');
    console.log('[WAIT] OKX 선물 마켓 로딩 대기... (' + delay + 'ms 후 재시도)');
    setTimeout(connectOkxFutures, delay);
    return;
  }

  console.log('[LINK] OKX 선물 WebSocket 연결 시도... (' + OKX_FUTURES_MARKETS.length + '개 페어)');
  okxFuturesSocket = new WebSocket('wss://ws.okx.com:8443/ws/v5/public');

  okxFuturesSocket.on('open', () => {
    WsReconnectManager.resetAttempts('okx_futures');  // 연결 성공 시 리셋
    console.log('[OK] OKX 선물 연결됨 - 배치 구독 시작...');
    okxFuturesWsReconnecting = false;
    
    // [2단계] 배치(Batch) 구독: 100개씩 나누어 전송
    const BATCH_SIZE = 100;
    const batches = [];
    for (let i = 0; i < OKX_FUTURES_MARKETS.length; i += BATCH_SIZE) {
      batches.push(OKX_FUTURES_MARKETS.slice(i, i + BATCH_SIZE));
    }
    
    console.log('   [PKG] OKX 선물: ' + batches.length + '개 배치로 분할 (' + OKX_FUTURES_MARKETS.length + '개 페어)');
    
    // 각 배치를 500ms 간격으로 전송 (Rate Limit 방지)
    batches.forEach((batch, index) => {
      setTimeout(() => {
        if (okxFuturesSocket && okxFuturesSocket.readyState === WebSocket.OPEN) {
          const subscribeMsg = {
            op: 'subscribe',
            //  마켓 배열에 정규화된 심볼('BTC')이 저장되어 있으므로,
            // OKX API 구독 시에는 '-USDT-SWAP'을 다시 붙여서 전송
            args: batch.map(symbol => ({
              channel: 'tickers',
              instId: symbol + '-USDT-SWAP'  // 'BTC' → 'BTC-USDT-SWAP'
            }))
          };
          okxFuturesSocket.send(JSON.stringify(subscribeMsg));
          console.log('   [OK] OKX 선물 배치 ' + (index + 1) + '/' + batches.length + ' 구독 완료 (' + batch.length + '개)');
        }
      }, index * 500);  // 500ms 간격
    });
  });
  
  okxFuturesSocket.on('message', (data) => {
    try {
      const message = JSON.parse(data.toString());
      if (message.data && Array.isArray(message.data)) {
        message.data.forEach(ticker => {
          const instId = ticker.instId;  // 'BTC-USDT-SWAP'
          const price = parseFloat(ticker.last);
          
          if (isNaN(price) || price <= 0) return;
          
          const open24h = parseFloat(ticker.open24h);
          const change24h = open24h > 0 ? ((price - open24h) / open24h * 100) : 0;
          
          //  심볼 표준화: 'BTC-USDT-SWAP' → 'BTC' (기초 자산만 저장)
          const symbol = instId.replace(/-USDT-SWAP$/, '');
          
          //  해외 거래소는 USD 가격 그대로 저장
          updateCoinPrice('OKX_FUTURES', symbol, price, change24h);
          
          //  틱을 CandleManager에 쌓고, 새 캔들 생성 시 모멘텀 갱신
          const result = CandleManager.updateFromTick('okx_futures', symbol, price, Date.now());
          if (result && result.isNewCandle && result.candleCount >= 10) {
            updateCoinMomentum('OKX_FUTURES', symbol);
          }
        });
      }
    } catch (err) {
      // 파싱 오류 무시
    }
  });
  
  okxFuturesSocket.on('error', (error) => console.error('OKX 선물 오류:', error.message));
  okxFuturesSocket.on('close', () => {
    okxFuturesWsReconnecting = true;
    const delay = WsReconnectManager.getNextDelay('okx_futures');
    console.log('[WARN] OKX 선물 WebSocket 연결 끊김 → ' + delay + 'ms 후 재연결');
    setTimeout(connectOkxFutures, delay);
  });
  
  // OKX는 30초마다 ping 필요
  const pingInterval = setInterval(() => {
    if (okxFuturesSocket && okxFuturesSocket.readyState === WebSocket.OPEN) {
      okxFuturesSocket.send('ping');
    } else {
      clearInterval(pingInterval);
    }
  }, 25000);
}

// ---
// 가격 업데이트
// ---

//  백엔드 쓰로틀링: 동일 symbol에 대해 100ms 간격 제한
const tickerLastSentTime = new Map();  // { 'UPBIT_SPOT:BTC': timestamp }
const TICKER_THROTTLE_MS = 100;  // 100ms 간격

// ════════════════════════════════════════════════════════════════
//  updateCoinPrice - 클라이언트별 타임프레임 대응
// - 각 클라이언트의 ws.clientTimeframe을 확인
// - momentumCacheMap에서 해당 타임프레임의 모멘텀 조회
// - 클라이언트별 맞춤 메시지 생성 및 전송
// ════════════════════════════════════════════════════════════════
function updateCoinPrice(exchange, symbol, price, change24h) {
  coinData = coinData.filter(c => !c.isDummy);
  const index = coinData.findIndex(c => c.exchange === exchange && c.symbol === symbol);
  
  // ---
  //  coinData 업데이트용 모멘텀 (서버 기본 타임프레임 기준)
  // - coinData는 전역 스냅샷이므로 기본 타임프레임 값 사용
  // - 실제 클라이언트 전송 시에는 각자 타임프레임 사용
  // ---
  let defaultMomentum = { up: undefined, down: undefined };
  const defaultTf = serverDefaultTimeframe || DEFAULT_TIMEFRAME || 240;
  
  // 업비트/빗썸: momentumCacheMap에서 조회
  //  모든 거래소 동일하게 fallback 처리
  const fallbackTfs = [240, 60, 30, 15, 5, 3, 1];
  
  if (exchange === 'UPBIT_SPOT') {
    const cache = momentumCacheMap.upbit[defaultTf];
    if (cache && cache.has(symbol)) {
      defaultMomentum = cache.get(symbol);
    }
    
    //  캐시 미스 시 다른 타임프레임에서 fallback
    if (defaultMomentum.up === undefined) {
      for (const tf of fallbackTfs) {
        if (tf === defaultTf) continue;
        const fallbackCache = momentumCacheMap.upbit[tf];
        if (fallbackCache && fallbackCache.has(symbol)) {
          defaultMomentum = fallbackCache.get(symbol);
          break;
        }
      }
    }
  } else if (exchange === 'BITHUMB_SPOT') {
    const cache = momentumCacheMap.bithumb[defaultTf];
    if (cache && cache.has(symbol)) {
      defaultMomentum = cache.get(symbol);
    }
    
    //  캐시 미스 시 다른 타임프레임에서 fallback
    if (defaultMomentum.up === undefined) {
      for (const tf of fallbackTfs) {
        if (tf === defaultTf) continue;
        const fallbackCache = momentumCacheMap.bithumb[tf];
        if (fallbackCache && fallbackCache.has(symbol)) {
          defaultMomentum = fallbackCache.get(symbol);
          break;
        }
      }
    }
  } else {
    // 글로벌 거래소: globalMomentumCache에서 조회
    const globalKey = exchange + ':' + symbol;
    const globalM = globalMomentumCache[defaultTf]?.get(globalKey);
    if (globalM) {
      defaultMomentum = globalM;
    }

    //  Multi-TF 캐시 미스 시 레거시 캐시 Fallback
    // - 글로벌 캐시가 비어 있어도 기존 기본 TF 값으로 "Calc..." 깜빡임 방지
    if (defaultMomentum.up === undefined) {
      const legacyCacheMap = {
        'BINANCE_SPOT': binanceSpotMomentumCache,
        'BINANCE_FUTURES': binanceFuturesMomentumCache,
        'OKX_SPOT': okxSpotMomentumCache,
        'OKX_FUTURES': okxFuturesMomentumCache
      };

      const legacyCache = legacyCacheMap[exchange];
      if (legacyCache && legacyCache.has(symbol)) {
        const legacyMomentum = legacyCache.get(symbol);
        defaultMomentum = legacyMomentum;
      }
    }
  }
  
  // 캐시 미스 시 기존 coinData 값 보존
  if (defaultMomentum.up === undefined && index >= 0 && coinData[index]) {
    defaultMomentum.up = coinData[index].upProbability;
    defaultMomentum.down = coinData[index].downProbability;
  }
  
  // coinData 업데이트 (서버 내부용)
  const coin = {
    exchange, symbol, price: Number(price),
    upProbability: defaultMomentum.up, 
    downProbability: defaultMomentum.down,
    change24h: Number.isFinite(change24h) ? Number(change24h) : 0,
    lastUpdate: new Date()
  };
  
  if (index >= 0) coinData[index] = coin;
  else coinData.push(coin);
  
  // 스냅샷 저장 (throttled)
  maybeSaveCoinDataSnapshot();
  
  // ---
  //  타임프레임별 그룹 전송 (2단계 최적화)
  // - Before: clients.forEach → 모든 클라이언트 순회, 각각 모멘텀 조회 (O(N*캐시조회))
  // - After: subscriptions.forEach → TF별로 모멘텀 1번만 조회 (O(7 + N*전송))
  // - 차등 스트리밍 유지: 보고 있는 심볼만 전송
  // ---
  if (typeof clients !== 'undefined' && clients.size > 0) {
    const throttleKey = exchange + ':' + symbol;
    const now = Date.now();
    const lastSent = tickerLastSentTime.get(throttleKey) || 0;
    
    if (now - lastSent >= TICKER_THROTTLE_MS) {
      tickerLastSentTime.set(throttleKey, now);
      
      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      //  핵심 최적화: TF별로 모멘텀 1번만 조회
      // - 모멘텀 캐시 조회: 클라이언트 N번 → TF 7번으로 감소
      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      const momentumByTf = new Map();  // TF → { up, down }
      const fallbackTfs = [240, 60, 30, 15, 5, 3, 1];
      
      // 각 타임프레임에 대해 모멘텀 미리 조회
      for (const tf of ALLOWED_TIMEFRAMES) {
        let momentum = { up: undefined, down: undefined };
        
        if (exchange === 'UPBIT_SPOT') {
          const cache = momentumCacheMap.upbit[tf];
          if (cache && cache.has(symbol)) {
            momentum = cache.get(symbol);
          }
          // Fallback
          if (momentum.up === undefined) {
            for (const fbTf of fallbackTfs) {
              if (fbTf === tf) continue;
              const fbCache = momentumCacheMap.upbit[fbTf];
              if (fbCache && fbCache.has(symbol)) {
                momentum = fbCache.get(symbol);
                break;
              }
            }
          }
        } else if (exchange === 'BITHUMB_SPOT') {
          const cache = momentumCacheMap.bithumb[tf];
          if (cache && cache.has(symbol)) {
            momentum = cache.get(symbol);
          }
          // Fallback
          if (momentum.up === undefined) {
            for (const fbTf of fallbackTfs) {
              if (fbTf === tf) continue;
              const fbCache = momentumCacheMap.bithumb[fbTf];
              if (fbCache && fbCache.has(symbol)) {
                momentum = fbCache.get(symbol);
                break;
              }
            }
          }
        } else {
          // 글로벌 거래소
          const globalKey = exchange + ':' + symbol;
          const globalM = globalMomentumCache[tf]?.get(globalKey);
          if (globalM) {
            momentum = globalM;
          }
          // 레거시 캐시 Fallback
          if (momentum.up === undefined) {
            const legacyCacheMap = {
              'BINANCE_SPOT': binanceSpotMomentumCache,
              'BINANCE_FUTURES': binanceFuturesMomentumCache,
              'OKX_SPOT': okxSpotMomentumCache,
              'OKX_FUTURES': okxFuturesMomentumCache
            };
            const legacyCache = legacyCacheMap[exchange];
            if (legacyCache && legacyCache.has(symbol)) {
              momentum = legacyCache.get(symbol);
            }
          }
        }
        
        momentumByTf.set(tf, momentum);
      }
      
      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      //  subscriptions 기반 TF별 전송
      // - 각 TF 그룹의 클라이언트에게만 해당 TF 모멘텀 전송
      // - 차등 스트리밍: 보고 있는 심볼만 전송
      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      subscriptions.forEach((wsSet, tf) => {
        if (!wsSet || wsSet.size === 0) return;
        
        const momentum = momentumByTf.get(tf) || { up: undefined, down: undefined };
        
        // 값 변환: undefined → 'CALC', null → '-'
        let upVal = 'CALC';
        let downVal = 'CALC';
        if (momentum.up !== undefined) {
          upVal = momentum.up === null ? '-' : momentum.up;
        }
        if (momentum.down !== undefined) {
          downVal = momentum.down === null ? '-' : momentum.down;
        }
        
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        //  JSON.stringify 최적화
        // - Before: 클라이언트당 1번 직렬화 (N번)
        // - After: TF당 1번 직렬화 (7번)
        // - 효과: 1,000명 기준 JSON.stringify 7,000번 → 7번 (99.9% 감소)
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        const visibleUpdate = ['U', throttleKey, coin.price, coin.change24h, upVal, downVal];
        const serializedMessage = JSON.stringify(visibleUpdate);
        
        //  같은 TF 클라이언트들에게는 동일한 메시지 전송
        // 단, 차등 스트리밍으로 보고 있는 클라이언트만 전송
        wsSet.forEach(ws => {
          if (ws.readyState !== WebSocket.OPEN) return;
          
          // 차등 스트리밍: 클라이언트가 이 심볼을 보고 있는지 확인
          const isWatching = ws.visibleExchanges?.has(throttleKey) || ws.visibleSymbols?.has(symbol);
          if (!isWatching) return;
          
          // 메시지 전송 (이미 직렬화된 문자열 재사용)
          ws.send(serializedMessage);
        });
      });
    }
  }
}

// ---
// API 엔드포인트
// ---

// ---
//  피드백 API
//  SECURITY_FEEDBACK_SALT 사용 (환경변수에서 로드)
// ---
// IP 해시 함수
function hashIP(ip) {
  return crypto.createHash('sha256').update(ip + SECURITY_FEEDBACK_SALT).digest('hex').substring(0, 16);
}

// 이메일 형식 검증
function isValidEmail(email) {
  if (!email || email.trim() === '') return true; // 빈 값 허용
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Rate Limit 체크 (간단한 인메모리 방식)
const feedbackRateLimit = new Map();
const FEEDBACK_RATE_LIMIT_MS = 60000; // 1분에 1회

function checkFeedbackRateLimit(ipHash) {
  const now = Date.now();
  const lastSubmit = feedbackRateLimit.get(ipHash);
  if (lastSubmit && (now - lastSubmit) < FEEDBACK_RATE_LIMIT_MS) {
    return false;
  }
  feedbackRateLimit.set(ipHash, now);
  return true;
}

// Rate Limit 맵 정리 (10분마다)
setInterval(() => {
  const now = Date.now();
  for (const [ipHash, timestamp] of feedbackRateLimit.entries()) {
    if ((now - timestamp) > FEEDBACK_RATE_LIMIT_MS * 10) {
      feedbackRateLimit.delete(ipHash);
    }
  }
}, 600000);

// POST /api/feedback - 피드백 저장
app.post('/api/feedback', (req, res) => {
  try {
    const { pagePath, category, content, email, userAgent, referrer, ts } = req.body;
    
    // 필수 필드 검증
    if (!pagePath || typeof pagePath !== 'string') {
      return res.status(400).json({ ok: false, error: 'invalid_pagePath' });
    }
    if (!category || !['bug', 'feature', 'other'].includes(category)) {
      return res.status(400).json({ ok: false, error: 'invalid_category' });
    }
    if (!content || typeof content !== 'string' || content.trim().length < 5) {
      return res.status(400).json({ ok: false, error: 'content_too_short' });
    }
    if (content.length > 2000) {
      return res.status(400).json({ ok: false, error: 'content_too_long' });
    }
    
    // 이메일 형식 검증 (선택)
    if (email && !isValidEmail(email)) {
      return res.status(400).json({ ok: false, error: 'invalid_email' });
    }
    
    //  IP 해시 (getClientIp 함수로 통일)
    const clientIP = getClientIp(req);
    const ipHash = hashIP(clientIP);
    
    // Rate Limit 체크
    if (!checkFeedbackRateLimit(ipHash)) {
      return res.status(429).json({ ok: false, error: 'rate_limit' });
    }
    
    // 피드백 데이터 구성
    const feedback = {
      id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
      created_at: new Date().toISOString(),
      page_path: pagePath.substring(0, 200),
      category: category,
      content: content.substring(0, 2000),
      email: (email || '').substring(0, 100),
      ip_hash: ipHash,
      user_agent: (userAgent || '').substring(0, 500),
      referrer: (referrer || '').substring(0, 200),
      client_ts: ts || null
    };
    
    // JSONL 파일에 추가
    const line = JSON.stringify(feedback) + '\n';
    fs.appendFile(FEEDBACK_FILE, line, (err) => {
      if (err) {
        console.error('[FEEDBACK] 저장 실패:', err.message);
        return res.status(500).json({ ok: false, error: 'save_failed' });
      }
      console.log('[FEEDBACK] 저장 완료: ' + feedback.id + ' (' + category + ')');
      res.json({ ok: true, id: feedback.id });
    });
    
  } catch (err) {
    console.error('[FEEDBACK] 처리 오류:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// GET /admin/feedback - 관리자 피드백 목록
//  ADMIN_API_KEY는 상단에서 환경변수로 로드됨
app.get('/admin/feedback', (req, res) => {
  const authKey = req.query.key;
  
  if (authKey !== ADMIN_API_KEY) {
    return res.status(401).send('<h1>Unauthorized</h1><p>Access denied. Use ?key=YOUR_KEY</p>');
  }
  
  // 피드백 파일 읽기
  let feedbacks = [];
  try {
    if (fs.existsSync(FEEDBACK_FILE)) {
      const data = fs.readFileSync(FEEDBACK_FILE, 'utf-8');
      feedbacks = data.trim().split('\n').filter(line => line).map(line => {
        try { return JSON.parse(line); } catch { return null; }
      }).filter(f => f).reverse(); // 최신순
    }
  } catch (err) {
    console.error('[ADMIN] 피드백 로드 실패:', err.message);
  }
  
  // 카테고리 라벨
  const categoryLabels = { bug: 'Bug', feature: 'Feature', other: 'Other' };
  const categoryColors = { bug: '#ef5350', feature: '#4caf50', other: '#9e9e9e' };
  
  // HTML 생성
  const adminHtml = '<!DOCTYPE html>' +
    '<html lang="ko">' +
    '<head>' +
    '<meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
    '<title>Feedback Admin - To The Moon List</title>' +
    '<style>' +
    '* { margin: 0; padding: 0; box-sizing: border-box; }' +
    'body { font-family: "Segoe UI", sans-serif; background: #0a0a0f; color: #e0e0e0; padding: 20px; }' +
    'h1 { color: #d4af37; margin-bottom: 20px; }' +
    '.stats { background: #1a1a24; padding: 15px; border-radius: 8px; margin-bottom: 20px; }' +
    '.stats span { margin-right: 20px; }' +
    '.feedback-list { display: flex; flex-direction: column; gap: 10px; }' +
    '.feedback-item { background: #1a1a24; border: 1px solid #333; border-radius: 8px; padding: 15px; }' +
    '.feedback-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }' +
    '.feedback-meta { color: #888; font-size: 12px; }' +
    '.feedback-category { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #fff; }' +
    '.feedback-content { background: #252530; padding: 10px; border-radius: 4px; margin: 10px 0; white-space: pre-wrap; word-break: break-word; }' +
    '.feedback-email { color: #64b5f6; font-size: 13px; }' +
    '.feedback-path { color: #888; font-size: 12px; }' +
    '.empty { text-align: center; color: #666; padding: 40px; }' +
    '</style>' +
    '</head>' +
    '<body>' +
    '<h1>Feedback Admin</h1>' +
    '<div class="stats">' +
    '<span>Total: ' + feedbacks.length + '</span>' +
    '<span style="color:#ef5350">Bug: ' + feedbacks.filter(f => f.category === 'bug').length + '</span>' +
    '<span style="color:#4caf50">Feature: ' + feedbacks.filter(f => f.category === 'feature').length + '</span>' +
    '<span style="color:#9e9e9e">Other: ' + feedbacks.filter(f => f.category === 'other').length + '</span>' +
    '</div>' +
    '<div class="feedback-list">' +
    (feedbacks.length === 0 ? '<div class="empty">No feedbacks yet</div>' : feedbacks.map(f => 
      '<div class="feedback-item">' +
      '<div class="feedback-header">' +
      '<span class="feedback-category" style="background:' + (categoryColors[f.category] || '#666') + '">' + (categoryLabels[f.category] || f.category) + '</span>' +
      '<span class="feedback-meta">' + f.created_at + ' | ID: ' + f.id + '</span>' +
      '</div>' +
      '<div class="feedback-content">' + escapeHtml(f.content) + '</div>' +
      (f.email ? '<div class="feedback-email">Email: ' + escapeHtml(f.email) + '</div>' : '') +
      '<div class="feedback-path">Path: ' + escapeHtml(f.page_path) + ' | IP: ' + f.ip_hash + '</div>' +
      '</div>'
    ).join('')) +
    '</div>' +
    '</body>' +
    '</html>';
  
  res.send(adminHtml);
});

// escapeHtml 헬퍼 (서버사이드용)
function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ════════════════════════════════════════════════════════════════
//  /api/coins - 타임프레임별 모멘텀 적용 (server259: tf 검증 추가)
// - 클라이언트가 ?tf=240 파라미터로 원하는 타임프레임 지정
// - 해당 타임프레임의 모멘텀이 적용된 coinData 반환
// - 유효하지 않은 tf 파라미터는 400 Bad Request 반환
// ════════════════════════════════════════════════════════════════
app.get('/api/coins', (req, res) => {
  // tf 파라미터 검증 (server259)
  const tfParam = req.query.tf;
  let requestedTf = DEFAULT_TIMEFRAME;
  
  if (tfParam != null && tfParam !== '') {
    const parsed = Number(tfParam);
    if (!Number.isFinite(parsed) || !isValidTimeframe(parsed)) {
      return res.status(400).json({ ok: false, error: 'invalid_timeframe' });
    }
    requestedTf = parsed;
  }
  
  // 해당 타임프레임의 모멘텀 캐시
  const upbitCache = momentumCacheMap.upbit[requestedTf];
  const bithumbCache = momentumCacheMap.bithumb[requestedTf];
  
  // coinData에 해당 타임프레임 모멘텀 적용
  const result = coinData.map(coin => {
    const newCoin = { ...coin };
    
    if (coin.exchange === 'UPBIT_SPOT' && upbitCache && upbitCache.has(coin.symbol)) {
      const m = upbitCache.get(coin.symbol);
      newCoin.upProbability = m.up;
      newCoin.downProbability = m.down;
    } else if (coin.exchange === 'BITHUMB_SPOT' && bithumbCache && bithumbCache.has(coin.symbol)) {
      const m = bithumbCache.get(coin.symbol);
      newCoin.upProbability = m.up;
      newCoin.downProbability = m.down;
    } else {
      // 글로벌 거래소
      const globalKey = coin.exchange + ':' + coin.symbol;
      const globalM = globalMomentumCache[requestedTf]?.get(globalKey);
      if (globalM) {
        newCoin.upProbability = globalM.up;
        newCoin.downProbability = globalM.down;
      }
    }
    
    return newCoin;
  });
  
  res.json(result);
});

// ---
// 타임프레임별 모멘텀 API - 캐시 Hit/Miss 로직 (명세 2)
//  전역 타임프레임 변경 제거 → 클라이언트별 독립 관리
// - 이 API는 서버의 기본 타임프레임만 변경 (Phase 1 백필용)
// - 실제 클라이언트 타임프레임은 WebSocket setTimeframe으로 관리
// ---
app.get('/api/momentum-timeframe', async (req, res) => {
  const unit = Number(req.query.unit);
  if (!isValidTimeframe(unit)) {
    return res.status(400).json({ ok: false, error: 'invalid_unit' });
  }
  
  //  서버 기본 타임프레임 변경 (Phase 1 백필용)
  // - 다중 클라이언트 환경에서는 이 값이 "최우선 수집 타임프레임"이 됨
  const previousTimeframe = serverDefaultTimeframe;
  serverDefaultTimeframe = unit;
  momentumTimeframe = unit;  // 하위 호환성
  
  // 다차원 캐시에서 해당 타임프레임 데이터 확인
  const upbitCache = momentumCacheMap.upbit[unit];
  const bithumbCache = momentumCacheMap.bithumb[unit];
  const hasCachedData = (upbitCache && upbitCache.size > 0) || (bithumbCache && bithumbCache.size > 0);
  
  if (hasCachedData) {
    // [OK] 캐시 Hit: 즉시 응답 + 백그라운드 갱신
    console.log('[FAST] [캐시 HIT] 타임프레임 ' + unit + '분 - 캐시된 데이터 즉시 반환');
    
    //  coinData 업데이트 제거 - 각 클라이언트가 자기 타임프레임 데이터를 받음
    // broadcastCoinData()가 클라이언트별 타임프레임에 맞게 전송
    
    // 클라이언트에 업데이트 브로드캐스트
    broadcastCoinData();
    
    // 백그라운드에서 갱신 (응답 블로킹 안 함)
    setImmediate(() => {
      console.log('[SYNC] [백그라운드] 타임프레임 ' + unit + '분 데이터 갱신 시작...');
      updateMomentumForTimeframe(unit).catch(err => {
        console.error('[ERROR] 백그라운드 갱신 오류:', err.message);
      });
    });
    
    return res.json({ ok: true, unit, cached: true, cacheSize: (upbitCache?.size || 0) + (bithumbCache?.size || 0) });
    
  } else {
    // ---
    //  캐시 Miss: 즉시 응답 + 백그라운드 갱신
    // ---
    console.log('[SCAN] [캐시 MISS] 타임프레임 ' + unit + '분 - 백그라운드 갱신 예약');
    
    //  즉시 응답 후 백그라운드에서 갱신 (Non-blocking)
    setImmediate(() => {
      console.log('[SYNC] [백그라운드] 타임프레임 ' + unit + '분 데이터 갱신 시작...');
      updateMomentumForTimeframe(unit).then(() => {
        broadcastCoinData();
        console.log('[OK] [백그라운드] 타임프레임 ' + unit + '분 갱신 완료!');
      }).catch(err => {
        console.error('[ERROR] 백그라운드 갱신 오류:', err.message);
      });
    });
    
    // 즉시 응답 (기존 데이터로)
    broadcastCoinData();
    return res.json({ ok: true, unit, cached: false, message: 'background_update_scheduled' });
  }
});

// ---
//  prefetchMissingMultiTfData 함수 제거됨
// - Phase 3 스트리밍 파이프라인에 통합되어 분리 함수 불필요
// - "청크 단위 수집 → 즉시 계산 → 즉시 방송" 로직으로 대체
// ---

// ---
// 특정 타임프레임의 모멘텀 갱신 함수 (명세 2)
// - UpbitApiScheduler가 타이밍 관리 (자체 딜레이 제거)
// ---
async function updateMomentumForTimeframe(unit) {
  // ════════════════════════════════════════════════════════════════
  //  마켓 로딩 체크를 Lock 획득 전으로 이동!
  // - 기존 버그: Lock 획득 후 return 시 finally 미실행 → Lock 영원히 남음
  // ════════════════════════════════════════════════════════════════
  if (!marketsLoaded) {
    console.log('⏳ 마켓 로딩 대기 중... (Lock 획득 전 리턴)');
    return;
  }
  
  // ════════════════════════════════════════════════════════════════
  //  "First Request Wins" Lock (동시접속 1000명+ 대응)
  // - 같은 TF에 대한 첫 번째 요청만 작업 수행
  // - 이후 요청들은 기존 작업 완료까지 대기 후 캐시된 결과 사용
  // - 다른 TF와는 완전 독립 (병렬 처리 가능)
  // 예시 (5분봉):
  //   클라이언트 A → Lock 획득, 작업 시작
  //   클라이언트 B → Lock 있음 → A 완료 대기
  //   클라이언트 C → Lock 있음 → A 완료 대기
  //   A 작업 완료 → Lock 해제 → B, C에게 캐시된 결과 전송
  // ════════════════════════════════════════════════════════════════
  
  // 이미 해당 TF 작업 진행 중이면 → 완료 대기!
  if (tfUpdateInProgress.has(unit)) {
    console.log('[LOCK] TF ' + unit + '분 이미 작업 중 → 완료 대기');
    try {
      await tfUpdateInProgress.get(unit);  // 기존 작업 완료 대기
      console.log('[LOCK] TF ' + unit + '분 대기 완료 → 캐시된 결과 사용');
    } catch (e) {
      console.log('[LOCK] TF ' + unit + '분 대기 중 에러 (무시): ' + e.message);
    }
    return;  // 캐시에서 결과 사용 (작업 재시작 안 함)
  }
  
  // 작업 Promise 생성
  let resolveWork, rejectWork;
  const workPromise = new Promise((resolve, reject) => {
    resolveWork = resolve;
    rejectWork = reject;
  });
  
  // Lock 획득
  tfUpdateInProgress.set(unit, workPromise);
  console.log('[LOCK] TF ' + unit + '분 Lock 획득 → 작업 시작');
  
  const startTime = Date.now();
  globalMomentumRequestId = startTime;  // 레거시 호환
  
  //  isCancelled() 완전 제거 - Lock이 중복 실행 방지
  // - 더 이상 "Latest Request Priority" 아님
  // - "First Request Wins" 패턴으로 변경
  
  // 타임아웃 여부 확인 헬퍼 함수 (유지)
  const isTimedOut = () => {
    if (Date.now() - startTime > MOMENTUM_TIMEOUT) {
      console.error('   [TIME] [Timeout] TF ' + unit + '분 작업 시간 초과로 강제 중단');
      return true;
    }
    return false;
  };
  
  //  currentRequestId → globalMomentumRequestId 수정
  console.log('[DATA] 타임프레임 ' + unit + '분 모멘텀 갱신 시작... (ID: ' + globalMomentumRequestId + ')');
  
  try {
    // 다차원 캐시 Map 초기화 (없으면 생성)
    if (!momentumCacheMap.upbit[unit]) momentumCacheMap.upbit[unit] = new Map();
    if (!momentumCacheMap.bithumb[unit]) momentumCacheMap.bithumb[unit] = new Map();
    
    // ════════════════════════════════════════════════════════════════
    //  3-거래소 완전 병렬 실행 (Promise.allSettled)
    // - 빗썸, 업비트, 글로벌 거래소를 동시에 시작하여 로딩 시간 최대한 단축!
    // - allSettled 사용: 한쪽 실패해도 다른 쪽 계속 실행 (안전성)
    // - 주의: Phase 1→2→3 순차 실행 아님! 3개가 동시에 시작됨!
    // ════════════════════════════════════════════════════════════════
    console.log('[PARALLEL] 3-거래소 병렬 모멘텀 계산 시작! (빗썸 + 업비트 + 글로벌)');
    
    await Promise.allSettled([
      // ════════════════════════════════════════════════════════════════
      // [BITHUMB] 빗썸 모멘텀 계산 (로컬 캔들 캐시 사용 → 가장 빠름)
      // ════════════════════════════════════════════════════════════════
      (async () => {
    // bithumbCandleCache(로컬 메모리)를 사용하므로 API 대기 불필요
    
    console.log('   [PARALLEL:BITHUMB] 빗썸 모멘텀 계산 시작...');
    let bithumbCount = 0;
    let bithumbSkipped = 0;
    
    for (const symbol of BITHUMB_MARKETS) {
      //  에러 격리 - 개별 심볼 에러는 로그만 남기고 계속 진행
      try {
        const momentum = await calculateBithumbMomentum(symbol, unit);
        
        // ════════════════════════════════════════════════════════════════
        //  방어적 업데이트 - 나쁜 값이 좋은 값을 덮어쓰지 않도록!
        // - 새 값이 undefined/null이고 기존 값이 숫자면 → 덮어쓰지 않음
        // ════════════════════════════════════════════════════════════════
        const oldVal = momentumCacheMap.bithumb[unit]?.get(symbol);
        const newValBad = (momentum.up === undefined || momentum.up === null);
        const oldValGood = (oldVal && typeof oldVal.up === 'number');
        
        if (newValBad && oldValGood) {
          // 기존 좋은 값 유지, 덮어쓰지 않음!
          bithumbSkipped++;
        } else {
          momentumCacheMap.bithumb[unit].set(symbol, momentum);
          
          if (unit === momentumTimeframe) {
            bithumbMomentumCache.set(symbol, momentum);
            
            // coinData 즉시 업데이트
            coinData.forEach(coin => {
              if (coin.symbol === symbol && coin.exchange === 'BITHUMB_SPOT') {
                coin.upProbability = momentum.up;
                coin.downProbability = momentum.down;
              }
            });
          }
        }
        bithumbCount++;
      } catch (err) {
        console.error('   [Skip] 빗썸 ' + symbol + ' 에러:', err.message);
      }
    }
    
    console.log('   [PARALLEL:BITHUMB] 빗썸 완료! (' + bithumbCount + '개, 보존: ' + bithumbSkipped + '개)');
    
    // 빗썸 완료 즉시 브로드캐스트 (먼저 끝나면 먼저 표시)
    if (bithumbCount > 0) {
      try {
        updateGlobalMomentumCaches();
        applyGlobalMomentumToCoinData();
        broadcastToTimeframe(unit);
        console.log('   [PARALLEL:BITHUMB] 빗썸 데이터 브로드캐스트!');
      } catch (e) {
        console.error('   [PARALLEL:BITHUMB] 브로드캐스트 실패:', e.message);
      }
    }
      })(),  //  BITHUMB IIFE 종료
      
      // ════════════════════════════════════════════════════════════════
      // [UPBIT] 업비트 모멘텀 계산 (API 호출 필요 → 중간 속도)
      // ════════════════════════════════════════════════════════════════
      (async () => {
    if (isTimedOut()) return;
    
    console.log('   [PARALLEL:UPBIT] 업비트 모멘텀 계산 시작... (API 호출)');
    let upbitCount = 0;
    let upbitSkipped = 0;
    
    for (const symbol of UPBIT_MARKETS) {
      if (isTimedOut()) return;
      
      try {
        const momentum = await calculateUpbitMomentum(symbol, unit);
        
        // ════════════════════════════════════════════════════════════════
        //  방어적 업데이트 - 나쁜 값이 좋은 값을 덮어쓰지 않도록!
        // ════════════════════════════════════════════════════════════════
        const oldVal = momentumCacheMap.upbit[unit]?.get(symbol);
        const newValBad = (momentum.up === undefined || momentum.up === null);
        const oldValGood = (oldVal && typeof oldVal.up === 'number');
        
        if (newValBad && oldValGood) {
          // 기존 좋은 값 유지, 덮어쓰지 않음!
          upbitSkipped++;
        } else {
          momentumCacheMap.upbit[unit].set(symbol, momentum);
          
          if (unit === momentumTimeframe) {
            upbitMomentumCache.set(symbol, momentum);
            
            // coinData 업데이트
            coinData.forEach(coin => {
              if (coin.symbol === symbol && coin.exchange === 'UPBIT_SPOT') {
                coin.upProbability = momentum.up;
                coin.downProbability = momentum.down;
              }
            });
          }
        }
        upbitCount++;
      } catch (err) {
        console.error('   [Skip] 업비트 ' + symbol + ' 에러:', err.message);
      }
    }
    
    console.log('   [PARALLEL:UPBIT] 업비트 완료! (' + upbitCount + '개, 보존: ' + upbitSkipped + '개)');
    
    // 업비트 완료 즉시 브로드캐스트
    if (upbitCount > 0) {
      try {
        updateGlobalMomentumCaches();
        applyGlobalMomentumToCoinData();
        broadcastToTimeframe(unit);
        console.log('   [PARALLEL:UPBIT] 업비트 데이터 브로드캐스트!');
      } catch (e) {
        console.error('   [PARALLEL:UPBIT] 브로드캐스트 실패:', e.message);
      }
    }
      })(),  //  UPBIT IIFE 종료
      
      // ════════════════════════════════════════════════════════════════
      // [GLOBAL] 글로벌 거래소 모멘텀 계산 (바이낸스 + OKX, API Rate Limit → 가장 느림)
      // ════════════════════════════════════════════════════════════════
      (async () => {
    if (isTimedOut()) return;
    
    console.log('   [PARALLEL:GLOBAL] 글로벌 거래소 모멘텀 계산 시작... (바이낸스 + OKX)');
    
    // 10분봉은 비활성화 상태
    if (unit === 10) {
      console.log('   [PARALLEL:GLOBAL] 10분봉은 비활성화 상태이므로 스킵');
    } else {
      // 거래소별 캐시 맵핑
      const globalCacheMap = {
        'binance_spot': binanceSpotMomentumCache,
        'binance_futures': binanceFuturesMomentumCache,
        'okx_spot': okxSpotMomentumCache,
        'okx_futures': okxFuturesMomentumCache
      };
      
      // exchange ID 변환 (소문자 → 대문자)
      const exchangeIdMap = {
        'binance_spot': 'BINANCE_SPOT',
        'binance_futures': 'BINANCE_FUTURES',
        'okx_spot': 'OKX_SPOT',
        'okx_futures': 'OKX_FUTURES'
      };
      
      let globalCount = 0;
      let globalErrorCount = 0;
      let fetchedCount = 0;
      let skippedCount = 0;
      
      // ---
      //  정시 갱신 체크 (Time-Aligned Broadcast)
      // - Round-Robin이 돌아도 약속된 시간(15분, 30분 등)이 아니면 방송 Skip
      // - 데이터를 방금 수집한 경우(wasFetched)는 예외로 즉시 방송
      // ---
      const shouldBroadcast = isTimeForUpdate(unit);
      
      // ---
      //  헬퍼 함수: 단일 심볼 모멘텀 계산 및 브로드캐스트
      //  360개 미만 데이터는 스킵 (리스트 펄떡임 방지)
      //  globalMomentumCache 저장 + 방어적 업데이트 추가!
      // ---
      const calculateAndBroadcast = (exchangeKey, symbol, skipBroadcast = false) => {
        try {
          const upperExchangeId = exchangeIdMap[exchangeKey];
          const cache = globalCacheMap[exchangeKey];
          //  현재 계산 중인 unit(타임프레임)을 세 번째 인자로 명시적 전달
          const momentum = calculateGlobalMomentum(upperExchangeId, symbol, unit);
          
          // ---
          //  데이터가 360개 미만이면 '설익은 데이터'이므로 무시
          // - aggregatedCount: 실제 계산에 사용된 캔들 수
          // - 데이터 수집 중(1~2초)에는 갱신 스킵 (화면 고정)
          // - 360개 확보 즉시 확정된 값으로 갱신
          // ---
          if (momentum.aggregatedCount < 360) {
            // 아직 데이터 수집 중 -> 갱신 스킵 (화면 고정)
            return;
          }
          
          // ════════════════════════════════════════════════════════════════
          //  절대 보호 - undefined/null은 무조건 저장 안 함!
          // - 기존 방어 로직 문제: oldValGood=false일 때 undefined 저장됨 (팀킬)
          // - 새 로직: "나쁜 값은 절대 입장 금지" (Gemini 분석 채택)
          // ════════════════════════════════════════════════════════════════
          if (momentum.up === undefined || momentum.up === null) {
            // 나쁜 값 → 절대 저장 안 함, 기존 값 유지!
            return false;
          }
          
          // 여기 도달하면 momentum.up은 숫자 → 안전하게 저장
          const globalKey = upperExchangeId + ':' + symbol;  // 예: BINANCE_SPOT:BTC
          
          if (!globalMomentumCache[unit]) {
            globalMomentumCache[unit] = new Map();
          }
          
          globalMomentumCache[unit].set(globalKey, momentum);
          
          // 레거시 캐시에도 저장 (기본 타임프레임용)
          if (unit === momentumTimeframe) {
            cache.set(symbol, momentum);
            
            // coinData 업데이트 및 브로드캐스트
            const coin = coinData.find(c => c.symbol === symbol && c.exchange === upperExchangeId);
            if (coin) {
              updateCoinPrice(upperExchangeId, symbol, coin.price, coin.change24h);
            }
          }
          
          globalCount++;
          return true;
        } catch (err) {
          globalErrorCount++;
          return false;
        }
      };
      
      // ---
      //  1. 바이낸스 현물 스트리밍 (병렬 청크)
      // ---
      if (BINANCE_SPOT_MARKETS && BINANCE_SPOT_MARKETS.length > 0) {
        console.log('   [IN] [1/4] 바이낸스 현물 스트리밍 (' + BINANCE_SPOT_MARKETS.length + '개)...');
        const chunks = chunkArray(BINANCE_SPOT_MARKETS, BINANCE_CHUNK_SIZE);
        
        for (const chunk of chunks) {
          if (isTimedOut()) break;
          
          // A. 데이터 부족분 식별 및 수집
          const missingItems = chunk.filter(symbol => 
            unit !== 1 && !CandleManager.hasEnoughMultiTfCandles('binance_spot', symbol, unit)
          );
          
          if (missingItems.length > 0) {
            await Promise.all(missingItems.map(async (symbol) => {
              try {
                const candles = await fetchBinanceSpotCandles(symbol, MIN_CANDLES_FOR_MOMENTUM + 10, unit);
                if (candles && candles.length > 0) {
                  CandleManager.initializeMultiTfCandles('binance_spot', symbol, unit, candles);
                  fetchedCount++;
                }
              } catch (err) { /* ignore */ }
            }));
          }
          skippedCount += chunk.length - missingItems.length;
          
          // B. 청크 내 모든 심볼 계산 (조건부 방송)
          //  데이터를 방금 수집했거나, 정시 갱신 타이밍일 때만 방송
          chunk.forEach(symbol => {
            const wasFetched = missingItems.includes(symbol);
            const skipBroadcast = !wasFetched && !shouldBroadcast;
            calculateAndBroadcast('binance_spot', symbol, skipBroadcast);
          });
          
          // C. API 호출이 있었다면 딜레이
          if (missingItems.length > 0) {
            await sleep(BINANCE_CHUNK_DELAY);
          } else {
            await new Promise(r => setImmediate(r));
          }
        }
      }
      
      // ---
      //  2. 바이낸스 선물 스트리밍 (병렬 청크)
      // ---
      if (BINANCE_FUTURES_MARKETS && BINANCE_FUTURES_MARKETS.length > 0) {
        if (isTimedOut()) { /* skip */ }
        else {
          console.log('   [IN] [2/4] 바이낸스 선물 스트리밍 (' + BINANCE_FUTURES_MARKETS.length + '개)...');
          const chunks = chunkArray(BINANCE_FUTURES_MARKETS, BINANCE_CHUNK_SIZE);
          
          for (const chunk of chunks) {
            if (isTimedOut()) break;
            
            const missingItems = chunk.filter(symbol => 
              unit !== 1 && !CandleManager.hasEnoughMultiTfCandles('binance_futures', symbol, unit)
            );
            
            if (missingItems.length > 0) {
              await Promise.all(missingItems.map(async (symbol) => {
                try {
                  const candles = await fetchBinanceFuturesCandles(symbol, MIN_CANDLES_FOR_MOMENTUM + 10, unit);
                  if (candles && candles.length > 0) {
                    CandleManager.initializeMultiTfCandles('binance_futures', symbol, unit, candles);
                    fetchedCount++;
                  }
                } catch (err) { /* ignore */ }
              }));
            }
            skippedCount += chunk.length - missingItems.length;
            
            //  데이터를 방금 수집했거나, 정시 갱신 타이밍일 때만 방송
            chunk.forEach(symbol => {
              const wasFetched = missingItems.includes(symbol);
              const skipBroadcast = !wasFetched && !shouldBroadcast;
              calculateAndBroadcast('binance_futures', symbol, skipBroadcast);
            });
            
            if (missingItems.length > 0) {
              await sleep(BINANCE_CHUNK_DELAY);
            } else {
              await new Promise(r => setImmediate(r));
            }
          }
        }
      }
      
      // ---
      //  3. OKX 현물 스트리밍 (순차 처리 - Rate Limit)
      // - OKX는 Rate Limit이 엄격하므로 순차 처리 유지
      // - 하지만 각 심볼 처리 직후 즉시 계산 & 방송
      // ---
      if (OKX_SPOT_MARKETS && OKX_SPOT_MARKETS.length > 0) {
        if (isTimedOut()) { /* skip */ }
        else {
          console.log('   [IN] [3/4] OKX 현물 스트리밍 (' + OKX_SPOT_MARKETS.length + '개, 순차 처리)...');
          
          for (const symbol of OKX_SPOT_MARKETS) {
            if (isTimedOut()) break;
            
            let needsFetch = unit !== 1 && !CandleManager.hasEnoughMultiTfCandles('okx_spot', symbol, unit);
            
            if (needsFetch) {
              try {
                // OKX 이어달리기: 2회 요청으로 360개 이상 확보
                let allCandles = [];
                let afterTs = null;
                
                for (let round = 0; round < 2; round++) {
                  const candles = await fetchOkxSpotCandles(symbol, 300, afterTs, unit);
                  if (!candles || candles.length === 0) break;
                  
                  allCandles = [...allCandles, ...candles];
                  
                  if (candles.length >= 300) {
                    afterTs = candles[candles.length - 1].timestamp;
                    await sleep(OKX_CHUNK_DELAY);
                  } else {
                    break;
                  }
                }
                
                if (allCandles.length > 0) {
                  CandleManager.initializeMultiTfCandles('okx_spot', symbol, unit, allCandles);
                  fetchedCount++;
                }
              } catch (err) { /* ignore */ }
              
              // Rate Limit 딜레이
              await sleep(OKX_CHUNK_DELAY);
            } else {
              skippedCount++;
            }
            
            //  계산 및 조건부 방송
            // - needsFetch(방금 수집한 경우)거나 shouldBroadcast(정시)일 때만 방송
            const skipBroadcast = !needsFetch && !shouldBroadcast;
            calculateAndBroadcast('okx_spot', symbol, skipBroadcast);
            
            // 데이터가 이미 있었다면 빠르게 넘어감
            if (!needsFetch) {
              await new Promise(r => setImmediate(r));
            }
          }
        }
      }
      
      // ---
      //  4. OKX 선물 스트리밍 (순차 처리 - Rate Limit)
      // ---
      if (OKX_FUTURES_MARKETS && OKX_FUTURES_MARKETS.length > 0) {
        if (isTimedOut()) { /* skip */ }
        else {
          console.log('   [IN] [4/4] OKX 선물 스트리밍 (' + OKX_FUTURES_MARKETS.length + '개, 순차 처리)...');
          
          for (const symbol of OKX_FUTURES_MARKETS) {
            if (isTimedOut()) break;
            
            let needsFetch = unit !== 1 && !CandleManager.hasEnoughMultiTfCandles('okx_futures', symbol, unit);
            
            if (needsFetch) {
              try {
                let allCandles = [];
                let afterTs = null;
                
                for (let round = 0; round < 2; round++) {
                  const candles = await fetchOkxFuturesCandles(symbol, 300, afterTs, unit);
                  if (!candles || candles.length === 0) break;
                  
                  allCandles = [...allCandles, ...candles];
                  
                  if (candles.length >= 300) {
                    afterTs = candles[candles.length - 1].timestamp;
                    await sleep(OKX_CHUNK_DELAY);
                  } else {
                    break;
                  }
                }
                
                if (allCandles.length > 0) {
                  CandleManager.initializeMultiTfCandles('okx_futures', symbol, unit, allCandles);
                  fetchedCount++;
                }
              } catch (err) { /* ignore */ }
              
              await sleep(OKX_CHUNK_DELAY);
            } else {
              skippedCount++;
            }
            
            //  계산 및 조건부 방송
            const skipBroadcast = !needsFetch && !shouldBroadcast;
            calculateAndBroadcast('okx_futures', symbol, skipBroadcast);
            
            if (!needsFetch) {
              await new Promise(r => setImmediate(r));
            }
          }
        }
      }
      
      console.log('   [PARALLEL:GLOBAL] 글로벌 완료! (계산: ' + globalCount + '개, 수집: ' + fetchedCount + '개, 기존: ' + skippedCount + '개, 실패: ' + globalErrorCount + '개)');
    }
      })()  //  GLOBAL IIFE 종료
    ]);  //  Promise.allSettled 종료 - 3-거래소 병렬 실행 완료
    
    console.log('[PARALLEL] 3-거래소 병렬 처리 완료!');
    
    // ---
    // 모멘텀 캐시 파일 저장 (30초 throttle)
    // ---
    maybeSaveMomentumCache();
    
    // ---
    //  순위표 강제 동기화 (Broadcast)
    // - 모든 청크 처리 완료 후 클라이언트에게 전체 순위표 전송
    // ---
    broadcastCoinData();
    
    const elapsedTime = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log('[OK] 타임프레임 ' + unit + '분 모멘텀 갱신 완료! (업비트: ' + momentumCacheMap.upbit[unit].size + '개, 빗썸: ' + momentumCacheMap.bithumb[unit].size + '개) [' + elapsedTime + '초]');
    
    //  성공 시 Lock 해제 및 대기 중인 클라이언트들에게 알림
    resolveWork();
    
  } catch (err) {
    console.error('[ERROR]  모멘텀 갱신 치명적 오류 (TF: ' + unit + '분):', err);
    rejectWork(err);  //  에러 시에도 대기 중인 클라이언트들에게 알림
  } finally {
    //  무조건 Lock 해제 (성공/실패 무관)
    tfUpdateInProgress.delete(unit);
    console.log('[LOCK] TF ' + unit + '분 Lock 해제');
  }
}

// ---
//  환율 변경 브로드캐스트
// - 클라이언트에게 새 환율을 알려 원화 환산가 갱신
// ---
function broadcastExchangeRate(newRate) {
  if (typeof clients !== 'undefined' && clients.size > 0) {
    const message = JSON.stringify({
      type: 'rate',
      usdtKrwRate: newRate
    });
    clients.forEach(ws => {
      if (ws.readyState === WebSocket.OPEN) ws.send(message);
    });
    console.log('[CAST]  환율 변경 브로드캐스트: 1 USDT = ' + newRate.toLocaleString() + ' KRW');
  }
}

// ---
// coinData 브로드캐스트 헬퍼 (타임프레임 변경 시 등)
//  순위표만 전송 (전체 데이터 X)
// ---
// ════════════════════════════════════════════════════════════════
//  특정 클라이언트에게 특정 타임프레임 데이터 전송
// - 순위표(R)뿐 아니라 상세 데이터(상승%/하락%)도 함께 전송!
// - 타임프레임 변경 즉시 화면이 갱신되도록 개선
// ════════════════════════════════════════════════════════════════
function sendCoinDataToClient(ws, timeframe) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  
  // ════════════════════════════════════════════════════════════════
  //  Fallback 타임프레임 순서 정의
  // - 요청된 TF에 데이터가 없으면 가까운 TF 순서대로 시도
  // ════════════════════════════════════════════════════════════════
  const fallbackOrder = {
    1: [1],
    3: [3, 1],
    5: [5, 3, 1],
    15: [15, 5, 3, 1],
    30: [30, 15, 5, 1],
    60: [60, 30, 15, 1],
    240: [240, 60, 30, 1]
  };
  const tfOrder = fallbackOrder[timeframe] || [timeframe, 1];
  
  // 해당 타임프레임의 모멘텀 캐시에서 데이터 적용
  const upbitCache = momentumCacheMap.upbit[timeframe];
  const bithumbCache = momentumCacheMap.bithumb[timeframe];
  
  // ════════════════════════════════════════════════════════════════
  //  디버깅: 캐시 상태 로그
  // ════════════════════════════════════════════════════════════════
  const upbitSize = upbitCache ? upbitCache.size : 0;
  const bithumbSize = bithumbCache ? bithumbCache.size : 0;
  const globalSize = globalMomentumCache[timeframe] ? globalMomentumCache[timeframe].size : 0;
  console.log('[DEBUG]  sendCoinDataToClient TF=' + timeframe + '분 | upbit=' + upbitSize + ', bithumb=' + bithumbSize + ', global=' + globalSize);
  
  // coinData 복사본에 해당 타임프레임 모멘텀 적용
  const coinDataWithMomentum = coinData.map(coin => {
    const newCoin = { ...coin };
    
    //  이전 타임프레임 데이터 잔상 방지
    newCoin.upProbability = undefined;
    newCoin.downProbability = undefined;
    
    // ════════════════════════════════════════════════════════════════
    //  업비트/빗썸: Fallback 적용
    // ════════════════════════════════════════════════════════════════
    if (coin.exchange === 'UPBIT_SPOT') {
      for (const tf of tfOrder) {
        const cache = momentumCacheMap.upbit?.[tf];
        if (cache && cache.has(coin.symbol)) {
          const m = cache.get(coin.symbol);
          newCoin.upProbability = m.up;
          newCoin.downProbability = m.down;
          break;
        }
      }
    } else if (coin.exchange === 'BITHUMB_SPOT') {
      for (const tf of tfOrder) {
        const cache = momentumCacheMap.bithumb?.[tf];
        if (cache && cache.has(coin.symbol)) {
          const m = cache.get(coin.symbol);
          newCoin.upProbability = m.up;
          newCoin.downProbability = m.down;
          break;
        }
      }
    } else {
      // ════════════════════════════════════════════════════════════════
      //  글로벌 거래소: Fallback 적용
      // ════════════════════════════════════════════════════════════════
      const globalKey = coin.exchange + ':' + coin.symbol;
      for (const tf of tfOrder) {
        const globalM = globalMomentumCache[tf]?.get(globalKey);
        if (globalM && globalM.up !== undefined) {
          newCoin.upProbability = globalM.up;
          newCoin.downProbability = globalM.down;
          break;
        }
      }
    }
    
    return newCoin;
  });
  
  // 상승확률순 정렬
  const sortedCoins = coinDataWithMomentum.sort((a, b) => {
    return (b.upProbability || 0) - (a.upProbability || 0);
  });
  
  // ════════════════════════════════════════════════════════════════
  //  순위표(R) 전송
  //  R 메시지에 timeframe 추가!
  //  R 메시지에 requestId도 추가! (동일 TF 재클릭 시 stale R 필터링용)
  // - 형식 변경: ['R', timeframe, 'UPBIT:BTC', ...] 
  //            → ['R', timeframe, requestId, 'UPBIT:BTC', ...]
  // - requestId가 undefined면 2개 요소만 (하위 호환)
  // ════════════════════════════════════════════════════════════════
  const rankingList = ['R', timeframe];  //  timeframe 추가!
  
  //  requestId가 있으면 3번째 요소로 추가
  // - 사용자 요청 응답(setTimeframe)에만 requestId 존재
  // - 이 값으로 클라이언트가 stale R 메시지를 필터링
  if (ws.lastRequestId !== undefined) {
    rankingList.push(ws.lastRequestId);
  }
  
  for (let i = 0; i < sortedCoins.length; i++) {
    const c = sortedCoins[i];
    rankingList.push(c.exchange + ':' + c.symbol);
  }
  ws.send(JSON.stringify(rankingList));
  
  // ════════════════════════════════════════════════════════════════
  //  상세 데이터(F = Full refresh) 전송
  // - 타임프레임 변경 시 즉시 상승%/하락% 값이 갱신되도록!
  // - 형식: { type: 'refresh', data: [[exchange, symbol, price, up, down, change], ...] }
  // ════════════════════════════════════════════════════════════════
  const refreshData = sortedCoins.map(c => {
    let upVal = 'CALC';
    let downVal = 'CALC';
    
    if (c.upProbability !== undefined) {
      upVal = c.upProbability === null ? '-' : c.upProbability;
    }
    if (c.downProbability !== undefined) {
      downVal = c.downProbability === null ? '-' : c.downProbability;
    }
    
    return [
      c.exchange,
      c.symbol,
      c.price,
      upVal,
      downVal,
      c.change24h
    ];
  });
  
  // ════════════════════════════════════════════════════════════════
  //  ws.lastSentMomentum 제거됨
  // - 이유: 전역 캐시(momentumCacheMap) fallback으로 충분
  // - 효과: 클라이언트당 ~80KB 메모리 절감
  // ════════════════════════════════════════════════════════════════
  
  // ════════════════════════════════════════════════════════════════
  //  refresh 응답에 requestId 포함
  // - 클라이언트가 stale response를 필터링할 수 있도록
  // ════════════════════════════════════════════════════════════════
  ws.send(JSON.stringify({
    type: 'refresh',
    data: refreshData,
    timeframe: timeframe,
    requestId: ws.lastRequestId  //  클라이언트가 보낸 요청 ID 그대로 반환
  }));
  
  // console.log(' 타임프레임 ' + timeframe + '분 데이터 전송 완료 (' + sortedCoins.length + '개 코인)');
}

// ════════════════════════════════════════════════════════════════
//  타임프레임별 브로드캐스트
// - 각 클라이언트에게 자기 타임프레임의 데이터만 전송
// - 동일 타임프레임 클라이언트끼리는 동일 메시지 공유 (효율성)
// ════════════════════════════════════════════════════════════════
function broadcastCoinData(msgType) {
  if (typeof clients === 'undefined' || clients.size === 0) return;
  
  // ════════════════════════════════════════════════════════════════
  //  순위표 브로드캐스트 최적화
  // - Before: 클라이언트마다 sendCoinDataToClient 호출 (N번 정렬 + N번 직렬화)
  // - After: TF당 1번만 buildCoinDataMessage 호출 (7번 정렬 + 7번 직렬화)
  // - 효과: 1,000명 기준 정렬 1,000번 → 7번 (99.3% 감소)
  // ════════════════════════════════════════════════════════════════
  
  let totalSent = 0;
  
  subscriptions.forEach((wsSet, timeframe) => {
    if (!wsSet || wsSet.size === 0) return;
    
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  핵심: TF당 1번만 메시지 생성
    // - 정렬: 1번
    // - JSON.stringify: 2번 (ranking + refresh)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    const messages = buildCoinDataMessage(timeframe);
    
    // 생성된 문자열을 해당 TF의 모든 클라이언트에게 전송
    wsSet.forEach(ws => {
      if (ws.readyState !== WebSocket.OPEN) return;
      
      try {
        ws.send(messages.ranking);
        ws.send(messages.refresh);
        totalSent++;
      } catch (e) {
        // 전송 오류 무시
      }
    });
  });
  
  if (totalSent > 0) {
    console.log('[BROADCAST]  ' + totalSent + '명 클라이언트에게 순위+데이터 전송 완료');
  }
}

// ---
//  SEO: robots.txt
// ---
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(`User-agent: *
Allow: /
Disallow: /api/
Disallow: /admin/

Sitemap: https://tothemoonlist.com/sitemap.xml
`);
});

// ---
//  SEO: sitemap.xml
// ---
app.get('/sitemap.xml', (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  res.type('application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://tothemoonlist.com/</loc>
    <lastmod>${today}</lastmod>
    <changefreq>always</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>
`);
});
// ---
//  SEO: og-image.png (카카오톡/페이스북 공유용)
// ---
const OG_IMAGE_BASE64 = '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';

app.get('/og-image.png', (req, res) => {
  const img = Buffer.from(OG_IMAGE_BASE64, 'base64');
  res.type('image/png');
  res.set('Cache-Control', 'public, max-age=86400');
  res.send(img);
});

// ---
// HTML 페이지 (명세서 전체 반영 - 다중 거래소 필터 + 리사이저 + 거래 버튼)
// ---
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title id="pageTitle">실시간 코인 순위 | To The Moon List</title>

<!--  Favicon 45도 회전 + 검은 테두리 |  SEO 메타 태그 (일상 용어로 변경) -->
<meta name="description" id="metaDescription" content="비트코인, 이더리움 등 200개 코인 실시간 시세와 급등 순위. 업비트, 빗썸, 바이낸스, OKX 거래소 지원.">
<meta name="keywords" content="코인 급등, 비트코인 단타, 코인 선물, 바이낸스 선물, 업비트 추천, 알트코인 급등, 실시간 코인, 코인 시세, 암호화폐 거래소, 코인 순위, crypto pump, bitcoin scalping, binance futures, altcoin trading, crypto exchange">

<!--  Favicon 45도 회전 + 검은 테두리 |  Open Graph -->
<meta property="og:type" content="website">
<meta property="og:url" content="https://tothemoonlist.com/">
<meta property="og:title" id="ogTitle" content="실시간 코인 순위 | To The Moon List">
<meta property="og:description" id="ogDescription" content="비트코인, 이더리움 등 200개 코인 실시간 시세와 급등 순위. 업비트, 빗썸, 바이낸스, OKX 거래소 지원.">
<meta property="og:locale" id="ogLocale" content="ko_KR">
<meta property="og:locale:alternate" content="en_US">
<meta property="og:site_name" content="To The Moon List">
<meta property="og:image" content="https://tothemoonlist.com/og-image.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">

<!--  Favicon 45도 회전 + 검은 테두리 |  Twitter Card -->
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" id="twTitle" content="실시간 코인 순위 | To The Moon List">
<meta name="twitter:description" id="twDescription" content="비트코인, 이더리움 등 200개 코인 실시간 시세와 급등 순위.">
<meta name="twitter:image" content="https://tothemoonlist.com/og-image.png">

<!--  hreflang 다국어 -->
<link rel="alternate" hreflang="ko" href="https://tothemoonlist.com/">
<link rel="alternate" hreflang="en" href="https://tothemoonlist.com/">
<link rel="alternate" hreflang="x-default" href="https://tothemoonlist.com/">
<link rel="canonical" href="https://tothemoonlist.com/">

<!--  Favicon - 45도 회전 + 검은 테두리 -->
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cg transform='rotate(45 12 12)'%3E%3Cpath fill='%23FFFFFF' stroke='%23333333' stroke-width='0.5' d='M12 2C12 2 7 4 7 12c0 2.5.5 4.5 1 6h8c.5-1.5 1-3.5 1-6 0-8-5-10-5-10zm0 11c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z'/%3E%3Cpath fill='%23d4af37' d='M5 18c0-1.5.5-3 1-4l-3 1v3l2 2v-2zM19 18c0-1.5-.5-3-1-4l3 1v3l-2 2v-2z'/%3E%3Cpath fill='%23FF9500' d='M9 18 L10 21 L10.5 19 L11 22 L12 19.5 L13 22 L13.5 19 L14 21 L15 18 Z'/%3E%3C/g%3E%3C/svg%3E">

<!--  Naver Search Advisor -->
<meta name="naver-site-verification" content="a67e8eb857820839283cecceac6196224a04b420" />

<!-- Google Analytics 4 (GA4) - server118: 쿠키 동의 후에만 로드 -->
<script>
  //  GA4 조건부 로딩 함수
  var gaLoaded = false;
  function loadAnalytics() {
    if (gaLoaded) return; // 중복 로딩 방지
    gaLoaded = true;
    
    // GA4 스크립트 동적 로딩
    var gaScript = document.createElement('script');
    gaScript.async = true;
    gaScript.src = 'https://www.googletagmanager.com/gtag/js?id=G-9WBWXF5N2N';
    document.head.appendChild(gaScript);
    
    // gtag 초기화
    window.dataLayer = window.dataLayer || [];
    function gtag(){dataLayer.push(arguments);}
    window.gtag = gtag;
    gtag('js', new Date());
    gtag('config', 'G-9WBWXF5N2N');
    
    console.log('[GA4] Analytics loaded with user consent');
  }
  
  // 페이지 로드 시: 이미 동의한 사용자는 즉시 GA4 로드
  (function() {
    try {
      var consent = localStorage.getItem('cookieConsent');
      if (consent === 'all') {
        loadAnalytics();
      }
    } catch (e) {
      // 시크릿 모드 등에서 localStorage 접근 불가 시 무시
    }
  })();
</script>

<style>
/* ============================================================
   기본 리셋 및 공통 스타일
   ============================================================ */
* { margin: 0; padding: 0; box-sizing: border-box; }

html, body {
  margin: 0;
  padding: 0;
}

body {
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  background: #0a0a0f;
  color: #e0e0e0;
  display: flex;
  flex-direction: column;
  height: 100vh;
  overflow: hidden;
}

/* ============================================================
   뷰 모드별 html/body 스타일
   ============================================================ */
html.view-with-chart,
body.view-with-chart {
  height: 100%;
  overflow: hidden;
}

/*  view-list-only 모드에서도 body 스크롤 비활성화 */
/* 오직 .coin-table-wrapper만 스크롤되도록 */
html.view-list-only,
body.view-list-only {
  height: 100vh;
  overflow: hidden;
}

/* ============================================================
   헤더
   ============================================================ */
.header {
  background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
  padding: 15px 20px;
  text-align: center;
  border-bottom: 2px solid #d4af37;
  flex-shrink: 0;
}

.header h1 {
  color: #d4af37;
  font-size: 1.8em;
  margin-bottom: 5px;
}

.header p {
  color: #888;
  font-size: 0.9em;
}

/* [UI] 헤더 로켓 아이콘 스타일 */
/*  오른쪽 기울기 + 불꽃 애니메이션 */
.header-icon {
  width: 42px;
  height: 42px;
  vertical-align: middle;
  margin-right: 8px;
  transform-origin: 50% 60%;
  transform: rotate(45deg);
  transition: transform 0.18s ease-out;
}

.header:hover .header-icon {
  transform: rotate(45deg) translateY(-2px);
}

/*  불꽃 애니메이션 */
@keyframes flicker {
  0%, 100% { opacity: 1; transform: scaleY(1); }
  25% { opacity: 0.85; transform: scaleY(0.92); }
  50% { opacity: 1; transform: scaleY(1.05); }
  75% { opacity: 0.9; transform: scaleY(0.95); }
}

.rocket-flame {
  /* animation removed */
  transform-origin: center top;
}

/*  BETA 뱃지 스타일 - 금색 (cursor: help 추가) */
.beta-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  margin-left: 8px;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 11px;
  letter-spacing: 0.08em;
  font-weight: 600;
  text-transform: uppercase;
  background: rgba(255, 255, 255, 0.10);
  border: 1px solid rgba(255, 255, 255, 0.25);
  color: #ffd86a;
  white-space: nowrap;
  cursor: help;
  vertical-align: middle;
}

@media (max-width: 600px) {
  .beta-badge {
    margin-left: 6px;
    padding: 1px 6px;
    font-size: 10px;
  }
}

/*  beta-notice 스타일 제거됨 (HTML에서 제거) */

/* ============================================================
   필터 영역
   ============================================================ */
.filters {
  background: #12121a;
  padding: 15px 20px;
  display: flex;
  gap: 15px;
  flex-wrap: wrap;
  justify-content: center;
  align-items: center;
  border-bottom: 1px solid #333;
  flex-shrink: 0;
}

.filter-group {
  display: flex;
  align-items: center;
  gap: 8px;
}

.filter-group label {
  color: #888;
  font-size: 0.85em;
}

/* ============================================================
   다중 거래소 필터 스타일 (명세서 1-3)
   ============================================================ */
.filter-left {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
}

/* ============================================================
    CSS 커스텀 도트 (이모지 대체)
   ============================================================ */
.dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 6px;
  flex-shrink: 0;
}

/* 거래소별 브랜드 컬러 */
.dot.upbit { background-color: #093687; box-shadow: 0 0 4px rgba(9, 54, 135, 0.6); }
.dot.bithumb { background-color: #f99400; box-shadow: 0 0 4px rgba(249, 148, 0, 0.6); }
.dot.binance { background-color: #FCD535; box-shadow: 0 0 4px rgba(252, 213, 53, 0.6); }
.dot.okx { background-color: #fff; box-shadow: 0 0 4px rgba(255, 255, 255, 0.6); }
.dot.bybit { background-color: #161a1e; border: 1px solid #444; }

/* KRW/USDT 그룹 라벨용 점 (선택사항) */
.dot.krw { background-color: #fff; opacity: 0.7; }
.dot.usdt { background-color: #26a69a; }

/*  선물(Futures) 마켓: 사각형 점 (형태 변수로 현물/선물 구분) */
/* - 현물(Spot): 원형(border-radius: 50%) - 코인/동전 이미지 */
/* - 선물(Futures): 사각형(border-radius: 0) - 칼각 사각형으로 원과 명확히 구분 */
/* [server263] border-radius: 2px -> 0 (원/사각형 구분 명확화) */
.dot.futures {
  border-radius: 0 !important;
}

/* ============================================================
    동적 아이콘 모드 (텍스트 잘림 시 자동 전환)
   - 기본: 텍스트 표시, dot 숨김
   - 아이콘 모드: dot 표시, 텍스트 숨김
   ============================================================ */

/* 테이블 내 dot은 기본적으로 숨김 (필터 버튼의 dot은 영향 없음) */
td:nth-child(1) .dot {
  display: none;
}

/* 아이콘 모드: dot 표시 */
.exchange-icon-mode td:nth-child(1) .dot {
  display: inline-block !important;
  width: 10px !important;
  height: 10px !important;
  min-width: 10px !important;
  min-height: 10px !important;
  margin: 0 !important;
  vertical-align: middle !important;
}

/* 아이콘 모드: 선물은 칼각 사각형 */
/* [server263] border-radius: 2px -> 0 */
.exchange-icon-mode td:nth-child(1) .dot.futures {
  border-radius: 0 !important;
}

/* 아이콘 모드: 텍스트 숨김 */
.exchange-icon-mode td:nth-child(1) .exchange-name {
  display: none !important;
}

/* 아이콘 모드: 셀 정렬 */
.exchange-icon-mode td:nth-child(1) {
  text-align: center !important;
}

/*  필터 버튼 스타일 모던화 */
.filter-left .filter-btn {
  display: inline-flex;
  align-items: center;
  padding: 6px 12px;
  border-radius: 4px;
  font-size: 0.85em;
  font-weight: 600;
  cursor: pointer;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.1);
  color: #888;
  transition: all 0.2s;
}

.filter-left .filter-btn input[type="checkbox"] {
  display: none;
}

.filter-left .filter-btn:hover {
  border-color: #666;
  color: #ccc;
}

.filter-left .filter-btn.active {
  background: rgba(255, 215, 0, 0.15);
  border-color: #d4af37;
  color: #d4af37;
}

/* ============================================================
    2단 그룹 레이아웃 스타일
   ============================================================ */
.exchange-filter-group {
  flex-direction: column;
  align-items: flex-start !important;
}

.exchange-group-wrapper {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.exchange-group {
  display: flex;
  align-items: center;
  gap: 8px;
}

.exchange-group .group-label {
  font-size: 0.85em;
  color: #ffffff;
  width: 90px;
  min-width: 90px;
  font-weight: bold;
  display: inline-flex;
  align-items: center;
  justify-content: flex-start;
  margin-right: 10px;
}

.exchange-group .filter-left {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.filter-all-btn {
  margin-left: 8px;
  padding: 5px 10px;
  font-size: 0.8em;
  background: #2a2a3a;
  border: 1px solid #555;
  color: #aaa;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s;
}

.filter-all-btn:hover {
  background: #3a3a4a;
  color: #fff;
}

/* ============================================================
    코인 검색창 스타일
   ============================================================ */
.search-filter-group {
  flex-shrink: 0;
}

.search-wrapper {
  position: relative;
  display: flex;
  align-items: center;
}

.search-icon-svg {
  position: absolute;
  left: 10px;
  top: 50%;
  transform: translateY(-50%);
  color: #888;
  width: 16px;
  height: 16px;
  pointer-events: none;
}

#searchInput {
  background: #1e1e2e;
  color: #e0e0e0;
  border: 1px solid #444;
  padding: 8px 12px 8px 32px;
  border-radius: 6px;
  font-size: 0.9em;
  width: 160px;
  max-width: 200px;
  transition: border-color 0.2s, box-shadow 0.2s;
}

#searchInput::placeholder {
  color: #666;
}

#searchInput:focus {
  outline: none;
  border-color: #d4af37;
  box-shadow: 0 0 0 2px rgba(212, 175, 55, 0.2);
}

/* 검색창 clear 버튼 (webkit 브라우저) */
#searchInput::-webkit-search-cancel-button {
  -webkit-appearance: none;
  height: 14px;
  width: 14px;
  background: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23888'%3E%3Cpath d='M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z'/%3E%3C/svg%3E") center/contain no-repeat;
  cursor: pointer;
}

/* 정렬 드롭다운 */
.filter-group select {
  background: #1e1e2e;
  color: #e0e0e0;
  border: 1px solid #444;
  padding: 8px 12px;
  border-radius: 6px;
  cursor: pointer;
}

/* 모멘텀 타임프레임 버튼 */
.momentum-timeframe {
  display: flex;
  gap: 5px;
  flex-wrap: wrap;
}

/* 모멘텀 섹션 (수정 3: 리스트 패널 내부) */
.momentum-section {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 15px;
  background: #12121a;
  border-bottom: 1px solid #333;
  flex-shrink: 0;
}

.momentum-section-label {
  color: #888;
  font-size: 0.85em;
  white-space: nowrap;
}

.momentum-btn {
  background: #1e1e2e;
  color: #888;
  border: 1px solid #444;
  padding: 6px 12px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
  transition: all 0.2s;
}

.momentum-btn:hover {
  border-color: #d4af37;
  color: #d4af37;
}

.momentum-btn.active {
  background: #d4af37;
  color: #000;
  border-color: #d4af37;
  font-weight: bold;
}

/*  비활성화된 모멘텀 버튼 (10분 등) */
.momentum-btn.disabled {
  opacity: 0.5;
  cursor: not-allowed;
  pointer-events: none;
  background-color: #2a2a3a;
  border-color: #444;
  color: #666;
}

/* ============================================================
   레이아웃 토글 버튼 스타일
   ============================================================ */
.view-toggle-buttons {
  display: inline-flex;
  border-radius: 4px;
  overflow: hidden;
  border: 1px solid #444;
}

.view-btn {
  background: #1b1b26;
  color: #ccc;
  border: none;
  padding: 6px 10px;
  font-size: 0.85rem;
  cursor: pointer;
  min-width: 70px;
  transition: all 0.2s;
}

.view-btn + .view-btn {
  border-left: 1px solid #444;
}

.view-btn:hover {
  background: #2a2a3a;
}

.view-btn.active {
  background: #d4af37;
  color: #000;
  font-weight: 600;
}

/* ============================================================
   메인 레이아웃 (명세서 3-3)
   ============================================================ */
.main-layout {
  display: flex;
  flex: 1;
  overflow: hidden;
  min-height: 0;
}

.main-layout.view-with-chart {
  display: flex;
  min-height: 0;
}

.main-layout.view-with-chart #coinListPanel {
  flex: 0 0 45%;
  min-width: 340px;
  max-width: 60%;
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
}

.main-layout.view-with-chart .coin-table-wrapper {
  flex: 1 1 auto;
  overflow-y: auto;
  overflow-anchor: none; /*  가상 스크롤 안정화 */
  background: #0d0d12;
}

.main-layout.view-with-chart #chartPanel {
  flex: 1 1 auto;
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
}

.main-layout.view-list-only {
  display: block;
}

.main-layout.view-list-only #coinListPanel {
  width: 100%;
  max-width: 100%;
  /*  가상 스크롤을 위한 설정 */
  display: flex;
  flex-direction: column;
  height: calc(100vh - 140px); /* 헤더 + 푸터 대략 높이 */
}

.main-layout.view-list-only .coin-table-wrapper {
  /*  가상 스크롤: 스크롤 영역 유지 */
  /*  overflow-anchor: none 추가 */
  flex: 1;
  overflow-y: auto;
  overflow-anchor: none;
  min-height: 0;
}

.main-layout.view-list-only #chartPanel,
.main-layout.view-list-only #resizer {
  display: none;
}

/* ============================================================
   리사이저 스타일 (명세서 3-2)
   ============================================================ */
#resizer {
  width: 6px;
  background: #333;
  cursor: col-resize;
  flex-shrink: 0;
  transition: background 0.2s;
  touch-action: none;
}

#resizer:hover {
  background: #d4af37;
}

body.resizing {
  cursor: col-resize;
  user-select: none;
}

body.resizing * {
  cursor: col-resize !important;
}

/* ============================================================
   테이블 스타일
   ============================================================ */
.coin-table-wrapper {
  background: #0d0d12;
  border-right: 1px solid #333;
  /*  가상 스크롤을 위한 스크롤 영역 설정 */
  /*  overflow-anchor: none - 가상 스크롤 안정화 핵심! */
  /* 브라우저의 Scroll Anchoring 기능이 DOM 변경 시 스크롤 위치를 강제 보정하는 것을 방지 */
  overflow-y: auto;
  overflow-x: hidden;
  overflow-anchor: none;
  flex: 1;
  min-height: 0;
}

/*  table-layout: fixed + 폰트 렌더링 최적화 */
table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
  text-rendering: optimizeSpeed;  /* 텍스트 그리기 비용 최소화 */
}

thead {
  position: sticky;
  top: 0;
  z-index: 10;
  background: #1a1a2e;
}

/*  tbody - 기본 렌더링 사용 (과도한 최적화 제거) */
#coinTableBody {
  /* 브라우저 기본 렌더링에 맡김 */
}

/*  th 고정 너비 - table-layout: fixed와 연동 */
th {
  padding: 12px 10px;
  text-align: left;
  color: #d4af37;
  font-weight: 600;
  font-size: 0.85em;
  border-bottom: 2px solid #d4af37;
  cursor: pointer;
  user-select: none;
  position: relative;
}

/*  정렬 화살표 스타일 */
th .sort-arrow {
  margin-left: 4px;
  font-size: 0.75em;
  color: #00d4ff;
  font-weight: bold;
}

th.sort-active {
  color: #00d4ff;
  background: rgba(0, 212, 255, 0.1);
}

/* 각 열의 고정 너비 (table-layout: fixed 필수) */
th:nth-child(1) { width: 13%; }  /* 거래소 */
th:nth-child(2) { width: 15%; }  /* 코인 */
th:nth-child(3) { width: 22%; }  /* 현재가 */
th:nth-child(4) { width: 15%; }  /* 24H */
th:nth-child(5) { width: 17%; }  /* 상승% */
th:nth-child(6) { width: 18%; }  /* 하락% */

th:hover {
  background: rgba(212, 175, 55, 0.1);
}

/*  td - pointer-events 기본값 복원 (클릭 기능 복구) */
/*  Compact Mode: 패딩 축소로 정보 밀도 향상 */
/*  td 줄바꿈 강제 방지 (Density 보장) */
td {
  padding: 6px 10px;
  border-bottom: 1px solid #1e1e2e;
  font-size: 0.9em;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 150px;
}

/*  코인 행 - transition 제거 (즉시 호버 반응) */
/*  Compact Mode: 행 높이 35px로 축소 (High Density) */
tr.coin-row {
  cursor: pointer;
  height: 35px;
  max-height: 35px;
  min-height: 35px;
  /* transition 제거: 마우스가 닿자마자 즉시 색상 변경 */
}

/*  가상 스크롤 스페이서 행 */
tr.virtual-spacer {
  height: 0;
  padding: 0;
  margin: 0;
  border: none;
  visibility: hidden;
}

tr.virtual-spacer td {
  padding: 0;
  margin: 0;
  border: none;
  height: 0;
}

/*  호버 효과 - 단순화 */
tr.coin-row:hover {
  background: #1a1a2e;
}

/* 선택된 행 (명세서 3-3) */
tr.selected-row {
  background: #1e3a5f;
}

/* 거래소 색상 */
.exchange-UPBIT_SPOT { color: #2196F3; }
.exchange-BITHUMB_SPOT { color: #FF9800; }
.exchange-BINANCE_SPOT { color: #F0B90B; }
.exchange-BINANCE_FUTURES { color: #F0B90B; }
.exchange-BYBIT_SPOT { color: #8B5CF6; }
.exchange-BYBIT_FUTURES { color: #8B5CF6; }

/* 가격 */
.price {
  font-weight: bold;
  color: #fff;
}

/* 변동률 */
.change-positive { color: #4CAF50; }
.change-negative { color: #f44336; }

/* 확률 */
/*  상승 확률 60% 이상: 초록색 */
.prob-high-up { color: #4CAF50; font-weight: bold; }
/*  하락 확률 60% 이상: 빨간색 */
.prob-high-down { color: #f44336; font-weight: bold; }
.prob-medium { color: #FFC107; }
.prob-low { color: #888; }

/*  로딩 중 상태 - 깜빡이는 애니메이션 */
.prob-calc {
  color: #666;
  font-size: 0.85em;
  animation: probPulse 1.5s ease-in-out infinite;
}

@keyframes probPulse {
  0%, 100% { opacity: 0.4; }
  50% { opacity: 1; }
}

/*  데이터 부족 상태 - 회색, 중앙 정렬 */
.prob-null {
  color: #555;
  opacity: 0.6;
  text-align: center;
}

/* ============================================================
   차트 패널 (명세서 3-3)
   ============================================================ */
#chartPanel {
  display: flex;
  flex-direction: column;
  width: 100%;
  height: 100%;
  background: #0d0d12;
}

#tv-chart-container {
  flex: 1;
  min-height: 0;
  width: 100%;
}

#tv-chart-container iframe {
  width: 100% !important;
  height: 100% !important;
}

.chart-placeholder {
  display: flex;
  align-items: center;
  justify-content: center;
  color: #666;
  font-size: 1.2em;
  width: 100%;
  height: 100%;
  flex: 1;
}

/* ============================================================
   거래 버튼 영역 (명세서 4-3)
   ============================================================ */
.exchange-links {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
  padding: 10px;
  background: #12121a;
  border-top: 1px solid #333;
}

.exchange-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  text-align: center;
  height: 40px;
  padding: 0 12px;
  border-radius: 6px;
  font-size: 0.85em;
  font-weight: 600;
  text-decoration: none;
  background: #1e1e2e;
  border: 1px solid #444;
  color: #ccc;
  transition: all 0.2s;
}

.exchange-btn:hover {
  background: #2a2a3a;
  border-color: #666;
  color: #fff;
}

.exchange-btn.active {
  background: rgba(212, 175, 55, 0.2);
  border-color: #d4af37;
  color: #d4af37;
  font-weight: 600;
}

/*  거래 버튼 내 거래소 아이콘 스타일 */
.exchange-btn .dot {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  margin-right: 6px;
  flex-shrink: 0;
}

.exchange-btn .dot.futures {
  border-radius: 0; /* [server263] 칼각 사각형 */
}

/* ============================================================
    레퍼럴(제휴) 라벨링 스타일 - 향후 사용 대비
   사용 예시:
   <button class="exchange-btn">
     바이낸스에서 거래하기
     <span class="badge-affiliate">제휴</span>
   </button>
   ============================================================ */
/*
.badge-affiliate {
  display: inline-block;
  margin-left: 6px;
  padding: 2px 6px;
  border-radius: 999px;
  font-size: 11px;
  line-height: 1;
  background: rgba(212, 175, 55, 0.3);
  color: #d4af37;
  opacity: 0.8;
}

.affiliate-note {
  font-size: 11px;
  color: #888;
  margin-top: 8px;
  text-align: center;
}

@media (max-width: 768px) {
  .affiliate-note {
    display: none;
  }
  .badge-affiliate {
    font-size: 10px;
    padding: 1px 4px;
  }
}
*/

/* ============================================================
   푸터
   ============================================================ */
.footer {
  background: #12121a;
  padding: 10px 20px;
  text-align: center;
  border-top: 1px solid #333;
  flex-shrink: 0;
}

.footer p {
  color: #666;
  font-size: 0.75em;
  margin: 2px 0;
}

.footer .warning {
  color: #f44336;
  font-weight: bold;
}

.footer-links {
  margin-top: 8px;
}

.footer-links a {
  color: #888;
  text-decoration: none;
  font-size: 0.75em;
  margin: 0 8px;
  cursor: pointer;
  transition: color 0.2s;
}

.footer-links a:hover {
  color: #d4af37;
  text-decoration: underline;
}

/* ============================================================
    푸터 접기/펼치기 스타일
   ============================================================ */
.footer-always-visible {
  /* 경고 문구는 항상 표시 */
}

.footer-collapsible {
  /* 기본 상태: 펼쳐짐 */
  display: block;
}

.footer-collapsible.collapsed {
  /* 접힌 상태: 숨김 */
  display: none;
}

.footer-toggle-btn {
  /*  시인성 대폭 강화 */
  background-color: rgba(255, 255, 255, 0.08);
  border: none;
  border-top: 1px solid #333;
  color: #ccc;
  cursor: pointer;
  width: 100%;
  padding: 8px 0;
  font-size: 1.2em;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.footer-toggle-btn:hover {
  background-color: rgba(255, 255, 255, 0.15);
  color: #d4af37;
}

/* ============================================================
   쿠키 동의 배너 (server114)
   ============================================================ */
.cookie-banner {
  display: none;
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  background: linear-gradient(to top, rgba(20, 20, 20, 0.98), rgba(30, 30, 30, 0.95));
  border-top: 1px solid #333;
  padding: 16px 20px;
  z-index: 10000;
  box-shadow: 0 -4px 20px rgba(0, 0, 0, 0.5);
}

.cookie-banner.show {
  display: block;
  animation: slideUp 0.3s ease-out;
}

@keyframes slideUp {
  from {
    transform: translateY(100%);
    opacity: 0;
  }
  to {
    transform: translateY(0);
    opacity: 1;
  }
}

.cookie-banner-content {
  max-width: 1200px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
}

.cookie-banner-text {
  flex: 1;
  color: #e0e0e0;
  font-size: 14px;
  line-height: 1.5;
}

.cookie-banner-text .cookie-icon {
  font-size: 18px;
  margin-right: 8px;
}

.cookie-banner-text a {
  color: #d4af37;
  text-decoration: underline;
  cursor: pointer;
}

.cookie-banner-text a:hover {
  color: #f0c040;
}

.cookie-banner-buttons {
  display: flex;
  gap: 10px;
  flex-shrink: 0;
}

.cookie-btn {
  padding: 10px 18px;
  border-radius: 6px;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;
  white-space: nowrap;
}

.cookie-btn-essential {
  background: transparent;
  border: 1px solid #666;
  color: #ccc;
}

.cookie-btn-essential:hover {
  border-color: #888;
  color: #fff;
  background: rgba(255, 255, 255, 0.05);
}

.cookie-btn-all {
  background: #d4af37;
  border: 1px solid #d4af37;
  color: #000;
}

.cookie-btn-all:hover {
  background: #e0c050;
  border-color: #e0c050;
}

/* 모바일 대응 */
@media (max-width: 768px) {
  .cookie-banner {
    padding: 14px 16px;
  }
  
  .cookie-banner-content {
    flex-direction: column;
    align-items: stretch;
    gap: 14px;
  }
  
  .cookie-banner-text {
    font-size: 13px;
    text-align: center;
  }
  
  .cookie-banner-buttons {
    justify-content: center;
  }
  
  .cookie-btn {
    padding: 10px 14px;
    font-size: 12px;
  }
}

/* ============================================================
   법적 고지 모달 (프론트 개선 3)
   ============================================================ */
.legal-modal-overlay {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.8);
  z-index: 10000;
  justify-content: center;
  align-items: center;
}

.legal-modal-overlay.active {
  display: flex;
}

.legal-modal {
  background: #1a1a2e;
  border: 1px solid #d4af37;
  border-radius: 12px;
  max-width: 600px;
  width: 90%;
  max-height: 80vh;
  overflow-y: auto;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
}

.legal-modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  border-bottom: 1px solid #333;
  position: sticky;
  top: 0;
  background: #1a1a2e;
  z-index: 1;
}

.legal-modal-header h3 {
  color: #d4af37;
  font-size: 1.1em;
  margin: 0;
}

.legal-modal-close {
  background: none;
  border: none;
  color: #888;
  font-size: 1.8em;
  cursor: pointer;
  line-height: 1;
  padding: 0;
  transition: color 0.2s;
}

.legal-modal-close:hover {
  color: #f44336;
}

.legal-modal-body {
  padding: 20px;
  color: #ccc;
  font-size: 0.9em;
  line-height: 1.7;
}

.legal-modal-body h4 {
  color: #d4af37;
  margin-top: 20px;
  margin-bottom: 10px;
  font-size: 1em;
}

.legal-modal-body h4:first-child {
  margin-top: 0;
}

.legal-modal-body p {
  margin-bottom: 12px;
}

.legal-modal-body ul {
  margin-left: 20px;
  margin-bottom: 12px;
}

.legal-modal-body li {
  margin-bottom: 6px;
}

/* ============================================================
   기타
   ============================================================ */
.loading {
  text-align: center;
  padding: 40px;
  color: #888;
}

.status-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 5px;
}

.status-live { background: #4CAF50; animation: pulse 2s infinite; }
.status-offline { background: #f44336; }

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

/* ============================================================
   시세 변동 Blinking 애니메이션 (프론트 개선 1)
   ============================================================ */
@keyframes flashUp {
  0% { background-color: rgba(76, 175, 80, 0.4); }
  100% { background-color: transparent; }
}

@keyframes flashDown {
  0% { background-color: rgba(244, 67, 54, 0.4); }
  100% { background-color: transparent; }
}

/*  시세 변동 Blinking 애니메이션 - 단순화 (GPU 강제 할당 제거) */
tr.flash-up {
  animation: flashUp 0.5s ease-out;
}

tr.flash-down {
  animation: flashDown 0.5s ease-out;
}

/* 필터 없음 안내 */
.no-filter-message {
  text-align: center;
  padding: 40px;
  color: #888;
  font-size: 1em;
}

/*  검색 결과 없음 안내 */
.no-result-message {
  text-align: center;
  padding: 60px 20px;
  color: #888;
  font-size: 1em;
}

/* ============================================================
    즐겨찾기 별 아이콘 스타일
   ============================================================ */
.star-icon {
  cursor: pointer;
  margin-right: 6px;
  font-size: 1.1em;
  color: #444;
  transition: color 0.2s, transform 0.1s;
  display: inline-block;
  vertical-align: middle;
  user-select: none;
  -webkit-user-select: none;
}

.star-icon:hover {
  color: #888;
  transform: scale(1.1);
}

.star-icon.active {
  color: #ffd700;
}

.star-icon.active:hover {
  color: #ffec8b;
}

/*  즐겨찾기 구분선 */
.fav-separator {
  border-bottom: 2px solid #d4af37 !important;
}

/* ============================================================
   모바일 전체화면 차트 모달 (명세서 5절)
   ============================================================ */
.mobile-chart-modal {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: #0a0a0f;
  z-index: 9999;
  flex-direction: column;
}

.mobile-chart-modal.active {
  display: flex;
}

.mobile-chart-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  background: #1a1a2e;
  border-bottom: 1px solid #333;
  flex-shrink: 0;
}

.mobile-chart-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 1em;
  color: #e0e0e0;
}

.mobile-chart-title .symbol {
  font-weight: bold;
  color: #d4af37;
}

.mobile-chart-title .exchange-tag {
  font-size: 0.85em;
  padding: 2px 8px;
  border-radius: 4px;
  background: rgba(255, 255, 255, 0.1);
}

.mobile-chart-title .exchange-tag.UPBIT_SPOT {
  color: #2196F3;
  background: rgba(33, 150, 243, 0.15);
}

.mobile-chart-title .exchange-tag.BITHUMB_SPOT {
  color: #FF9800;
  background: rgba(255, 152, 0, 0.15);
}

.mobile-chart-close {
  background: none;
  border: none;
  color: #888;
  font-size: 1.5em;
  cursor: pointer;
  padding: 4px 8px;
  line-height: 1;
}

.mobile-chart-close:hover {
  color: #fff;
}

.mobile-chart-body {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
}

#mobile-tv-chart-container {
  flex: 1;
  min-height: 0;
  width: 100%;
}

#mobile-tv-chart-container iframe {
  width: 100% !important;
  height: 100% !important;
}

.mobile-exchange-links {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 6px;
  padding: 8px;
  background: #12121a;
  border-top: 1px solid #333;
  flex-shrink: 0;
}

.mobile-exchange-links .exchange-btn {
  height: 36px;
  font-size: 0.85em;
}

/* ============================================================
   모바일 반응형 (명세서 5-1)
   ============================================================ */
@media (max-width: 768px) {
  /* [server262] 헤더 Safe Zone - 언어 버튼/BETA 배지와 겹침 방지 */
  .header h1 {
    font-size: 1.3em;
    padding-right: 95px; /* 언어 버튼 2개(~80px) + 여백 */
    word-break: keep-all;
  }
  
  .header p {
    font-size: 0.8em;
  }
  
  /*  필터 영역 여백 축소 (더 조밀하게) */
  .filters {
    padding: 8px 8px;
    gap: 6px;
  }
  
  .filter-group {
    flex-wrap: wrap;
    gap: 4px;
  }
  
  .filter-group label {
    font-size: 0.75em;
  }
  
  /*  모바일 검색창 스타일 */
  #searchInput {
    width: 120px;
    padding: 6px 10px 6px 28px;
    font-size: 0.8em;
  }
  
  .search-icon-svg {
    width: 14px;
    height: 14px;
    left: 8px;
  }
  
  .filter-left {
    gap: 3px;
  }
  
  /*  모바일 필터 버튼 - 도트 유지하면서 조밀화 */
  .filter-left .filter-btn {
    padding: 4px 8px;
    font-size: 0.75em;
    font-weight: 600;
  }
  
  /*  모바일에서 도트 크기 약간 축소 */
  .filter-left .filter-btn .dot {
    width: 6px;
    height: 6px;
    margin-right: 4px;
  }
  
  /*  모바일 별 아이콘 터치 영역 확보 */
  .star-icon {
    padding: 0 5px;
    font-size: 1em;
  }
  
  /*  거래소 버튼 조밀화 */
  .exchange-btn {
    padding: 0 8px;
    height: 36px;
    font-size: 0.8em;
  }
  
  /*  모바일 2단 그룹 레이아웃 - 더 조밀하게 */
  .exchange-group-wrapper {
    gap: 4px;
  }
  
  .exchange-group {
    flex-wrap: wrap;
    gap: 3px;
  }
  
  .exchange-group .group-label {
    min-width: 80px;
    font-size: 0.7em;
  }
  
  .momentum-timeframe {
    gap: 2px;
  }
  
  .momentum-btn {
    padding: 4px 6px;
    font-size: 0.7em;
  }
  
  /*  모멘텀 섹션 모바일 스타일 - 더 조밀하게 */
  .momentum-section {
    padding: 6px 8px;
    flex-wrap: wrap;
    gap: 4px;
  }
  
  .momentum-section-label {
    font-size: 0.7em;
    width: 100%;
    margin-bottom: 3px;
  }
  
  .view-toggle-group {
    display: none; /* 모바일에서는 레이아웃 토글 숨김 */
  }
  
  /*  모바일에서도 단일 스크롤 소스 유지 (네이티브 앱 스크롤 경험) */
  /* body 스크롤 비활성화 - 오직 테이블 영역만 스크롤 */
  html, body {
    height: 100% !important;
    overflow: hidden !important;
  }
  
  /*  모바일 Flex 레이아웃 - 남은 공간을 리스트가 채움 */
  .main-layout {
    display: flex !important;
    flex-direction: column !important;
    height: calc(100vh - 120px) !important; /* 헤더 + 푸터 높이 제외 */
    overflow: hidden !important;
  }
  
  .main-layout #coinListPanel {
    width: 100% !important;
    flex: 1 1 auto !important;
    display: flex !important;
    flex-direction: column !important;
    min-height: 0 !important;
    overflow: hidden !important;
  }
  
  /*  coin-table-wrapper가 유일한 스크롤 컨테이너 */
  .main-layout .coin-table-wrapper {
    flex: 1 1 auto !important;
    overflow-y: auto !important;
    overflow-x: hidden !important;
    overflow-anchor: none !important; /* 가상 스크롤 안정화 */
    min-height: 0 !important;
    -webkit-overflow-scrolling: touch; /* iOS 부드러운 스크롤 */
  }
  
  .main-layout #chartPanel,
  .main-layout #resizer {
    display: none !important;
  }
  
  /* ============================================================
      모바일 테이블 CSS 다이어트 (아이폰 최적화)
     - 좁은 폭(390px 등)에서도 6개 컬럼 시원하게 표시
     ============================================================ */
  
  /* [server262] 모바일 거래소 컬럼 - 아이콘 모드 강제 적용
     - 문제: checkExchangeColumnOverflow()가 iOS에서 타이밍 이슈로 실패
     - 해결: CSS로 강제 적용하여 JavaScript 의존성 제거
     - 참고: 기존 .exchange-icon-mode CSS(10374-10397)와 동일 효과 */
  td:nth-child(1) .exchange-name {
    display: none !important;
  }
  
  td:nth-child(1) .dot {
    display: inline-block !important;
    width: 8px !important;
    height: 8px !important;
    margin: 0 !important;
    vertical-align: middle !important;
  }
  
  /* 선물 거래소는 칼각 사각형 dot */
  /* [server263] border-radius: 2px -> 0 */
  td:nth-child(1) .dot.futures {
    border-radius: 0 !important;
  }
  
  th:nth-child(1), td:nth-child(1) {
    text-align: center !important;
  }
  
  /* 모바일 전용 테이블 셀 스타일 */
  th, td {
    padding: 6px 2px !important;           /* 좌우 패딩 극단적 축소 */
    font-size: 11px !important;            /* 글꼴 축소로 한 줄 표시 보장 */
    letter-spacing: -0.5px !important;     /* 자간 좁혀 숫자 가독성 확보 */
    white-space: nowrap !important;        /* 줄바꿈 강제 방지 */
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    max-width: 0 !important;               /* table-layout: fixed 트릭 */
  }
  
  /*  모바일 전용 컬럼 너비 재분배 */
  th:nth-child(1) { width: 12% !important; font-size: 11px !important; }  /* 거래소 헤더 */
  td:nth-child(1) { width: 12% !important; }  /* 거래소 */
  th:nth-child(2), td:nth-child(2) { width: 14% !important; }  /* 코인 */
  th:nth-child(3), td:nth-child(3) { width: 26% !important; }  /* 현재가 */
  th:nth-child(4), td:nth-child(4) { width: 14% !important; }  /* 24H */
  th:nth-child(5), td:nth-child(5) { width: 17% !important; }  /* 상승% */
  th:nth-child(6), td:nth-child(6) { width: 17% !important; }  /* 하락% */
  
  .footer {
    padding: 8px 12px;
  }
  
  .footer p {
    font-size: 0.7em;
  }
}

/* 태블릿 가로 모드 */
@media (min-width: 769px) and (max-width: 1024px) {
  .main-layout.view-with-chart #coinListPanel {
    flex: 0 0 40% !important;
    min-width: 300px;
  }
}

/*  해외 거래소 USDT 표시 */
.currency-usdt {
  color: #26a69a;
  font-size: 0.75em;
  font-weight: bold;
  margin-left: 2px;
  opacity: 0.8;
}

/*  환산 가격 표시 */
.converted-price {
  color: #888;
  font-size: 0.9em;
}

/*  글로벌 거래소 배지 */
.exchange-badge {
  display: inline-block;
  padding: 1px 4px;
  border-radius: 3px;
  font-size: 0.65em;
  font-weight: bold;
  margin-left: 4px;
  vertical-align: middle;
}
.exchange-badge.binance { background: #f0b90b; color: #000; }
.exchange-badge.okx { background: #000; color: #fff; }
.exchange-badge.futures { background: #ef5350; color: #fff; }

/* ============================================================
    언어 토글 버튼 스타일
   ============================================================ */
.lang-toggle-wrapper {
  position: fixed;
  top: 10px;
  right: 15px;
  z-index: 9999;
  display: flex;
  gap: 5px;
}

.lang-btn {
  background: rgba(30, 30, 40, 0.9);
  border: 1px solid #333;
  border-radius: 4px;
  padding: 5px 10px;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.2s;
  color: #888;
}

.lang-btn:hover {
  border-color: #d4af37;
}

.lang-btn.active {
  border-color: #d4af37;
  color: #d4af37;
  background: rgba(212, 175, 55, 0.1);
}

/* ============================================================
    피드백 버튼 및 모달 스타일
   ============================================================ */
.feedback-btn {
  position: fixed;
  bottom: 80px;
  right: 20px;
  z-index: 9997;
  background: linear-gradient(135deg, #5c6bc0, #3f51b5);
  color: #fff;
  border: none;
  border-radius: 20px;
  padding: 8px 14px;
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
  box-shadow: 0 4px 12px rgba(63, 81, 181, 0.35);
  transition: transform 0.2s, box-shadow 0.2s;
  font-family: 'Segoe UI', sans-serif;
}

.feedback-btn:hover {
  transform: scale(1.05);
  box-shadow: 0 6px 16px rgba(63, 81, 181, 0.45);
}

/* 피드백 모달 오버레이 */
.feedback-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.7);
  z-index: 10000;
  display: none;
  align-items: center;
  justify-content: center;
}

.feedback-overlay.open {
  display: flex;
}

/* 피드백 모달 */
.feedback-modal {
  background: #1a1a24;
  border: 1px solid #333;
  border-radius: 12px;
  width: 90%;
  max-width: 420px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.feedback-modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  border-bottom: 1px solid #333;
  background: linear-gradient(135deg, #252530, #1e1e28);
}

.feedback-modal-title {
  font-size: 16px;
  font-weight: 600;
  color: #d4af37;
}

.feedback-modal-close {
  background: none;
  border: none;
  color: #888;
  font-size: 24px;
  cursor: pointer;
  padding: 0;
  line-height: 1;
}

.feedback-modal-close:hover {
  color: #fff;
}

.feedback-modal-body {
  padding: 20px;
}

.feedback-form-group {
  margin-bottom: 16px;
}

.feedback-label {
  display: block;
  font-size: 13px;
  font-weight: 500;
  color: #aaa;
  margin-bottom: 6px;
}

.feedback-select,
.feedback-textarea,
.feedback-input {
  width: 100%;
  background: #252530;
  border: 1px solid #444;
  border-radius: 6px;
  color: #e0e0e0;
  font-size: 14px;
  padding: 10px 12px;
  font-family: inherit;
  transition: border-color 0.2s;
}

.feedback-select:focus,
.feedback-textarea:focus,
.feedback-input:focus {
  outline: none;
  border-color: #5c6bc0;
}

.feedback-textarea {
  min-height: 120px;
  resize: vertical;
}

.feedback-char-count {
  text-align: right;
  font-size: 11px;
  color: #666;
  margin-top: 4px;
}

.feedback-char-count.warning {
  color: #ef5350;
}

.feedback-modal-footer {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
  padding: 16px 20px;
  border-top: 1px solid #333;
  background: #1a1a24;
}

.feedback-cancel-btn,
.feedback-submit-btn {
  padding: 10px 20px;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: background 0.2s;
}

.feedback-cancel-btn {
  background: #333;
  border: 1px solid #444;
  color: #aaa;
}

.feedback-cancel-btn:hover {
  background: #444;
  color: #fff;
}

.feedback-submit-btn {
  background: linear-gradient(135deg, #5c6bc0, #3f51b5);
  border: none;
  color: #fff;
}

.feedback-submit-btn:hover {
  background: linear-gradient(135deg, #7986cb, #5c6bc0);
}

.feedback-submit-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

/* 피드백 상태 메시지 */
.feedback-status {
  padding: 12px;
  border-radius: 6px;
  text-align: center;
  margin-top: 10px;
  font-size: 13px;
}

.feedback-status.success {
  background: rgba(76, 175, 80, 0.15);
  color: #4caf50;
  border: 1px solid rgba(76, 175, 80, 0.3);
}

.feedback-status.error {
  background: rgba(239, 83, 80, 0.15);
  color: #ef5350;
  border: 1px solid rgba(239, 83, 80, 0.3);
}

/* ============================================================
    채팅 UI 스타일 (우측 하단 말풍선)
   ============================================================ */
.chat-container {
  position: fixed;
  bottom: 20px;
  right: 20px;
  z-index: 9998;
  font-family: 'Segoe UI', sans-serif;
}

.chat-toggle-btn {
  width: 50px;
  height: 50px;
  border-radius: 50%;
  background: linear-gradient(135deg, #d4af37, #b8962e);
  border: none;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 4px 15px rgba(212, 175, 55, 0.3);
  transition: transform 0.2s, box-shadow 0.2s;
  position: relative;
}

.chat-toggle-btn:hover {
  transform: scale(1.1);
  box-shadow: 0 6px 20px rgba(212, 175, 55, 0.4);
}

/*  채팅 플로팅 버튼 아이콘 - 흰색 말풍선 */
.chat-toggle-icon {
  width: 24px;
  height: 24px;
  fill: #FFFFFF;
  filter: drop-shadow(0 1px 2px rgba(0, 0, 0, 0.5));
  display: block;
}

.chat-badge {
  position: absolute;
  top: -5px;
  right: -5px;
  background: #ef5350;
  color: #fff;
  font-size: 11px;
  font-weight: bold;
  min-width: 18px;
  height: 18px;
  border-radius: 9px;
  display: none;
  align-items: center;
  justify-content: center;
  padding: 0 4px;
}

.chat-badge.show {
  display: flex;
}

.chat-window {
  position: absolute;
  bottom: 60px;
  right: 0;
  width: 320px;
  height: 400px;
  background: #1a1a24;
  border: 1px solid #333;
  border-radius: 12px;
  display: none;
  flex-direction: column;
  overflow: hidden;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
}

.chat-window.open {
  display: flex;
}

.chat-header {
  background: linear-gradient(135deg, #252530, #1e1e28);
  padding: 12px 15px;
  border-bottom: 1px solid #333;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.chat-header-title {
  font-size: 14px;
  font-weight: 600;
  color: #d4af37;
}

.chat-header-count {
  font-size: 11px;
  color: #888;
  display: none;
}

.chat-close-btn {
  background: none;
  border: none;
  color: #888;
  cursor: pointer;
  padding: 4px;
  line-height: 1;
  display: flex;
  align-items: center;
  justify-content: center;
}

.chat-close-icon {
  width: 24px;
  height: 24px;
  fill: currentColor;
  transition: fill 0.2s;
}

.chat-close-btn:hover {
  color: #fff;
}

/*  닉네임 변경 바 */
.chat-nickname-bar {
  background: #1a1a20;
  padding: 8px 12px;
  border-bottom: 1px solid #333;
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
}

.chat-nickname-label {
  color: #888;
}

.chat-nickname-value {
  color: #d4af37;
  font-weight: 600;
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.chat-nickname-edit-btn {
  background: #333;
  border: 1px solid #444;
  color: #ccc;
  padding: 3px 8px;
  border-radius: 4px;
  font-size: 11px;
  cursor: pointer;
  transition: all 0.2s;
}

.chat-nickname-edit-btn:hover {
  background: #444;
  color: #fff;
  border-color: #555;
}

/*  우클릭 컨텍스트 메뉴 */
.chat-context-menu {
  position: fixed;
  display: none;
  z-index: 9999;
  background: #1e1e24;
  border: 1px solid #444;
  border-radius: 6px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
  min-width: 160px;
  overflow: hidden;
}

.chat-context-menu ul {
  list-style: none;
  margin: 0;
  padding: 4px 0;
}

.chat-context-menu li {
  padding: 10px 14px;
  cursor: pointer;
  font-size: 13px;
  color: #ddd;
  display: flex;
  align-items: center;
  gap: 8px;
  transition: background 0.15s;
}

.chat-context-menu li:hover {
  background: #2a2a30;
}

.chat-context-menu li.danger {
  color: #ff6b6b;
}

.chat-context-menu li.danger:hover {
  background: rgba(255, 107, 107, 0.15);
}

/*  삭제된 메시지 스타일 */
.chat-message-deleted {
  background: transparent !important;
  opacity: 0.6;
  font-style: italic;
}

.chat-message-deleted .deleted-stub {
  color: #888;
  font-size: 12px;
}

.chat-messages {
  flex: 1;
  overflow-y: auto;
  padding: 10px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.chat-message {
  padding: 8px 12px;
  border-radius: 8px;
  font-size: 13px;
  line-height: 1.4;
  max-width: 90%;
  word-break: break-word;
  -webkit-user-select: none;
  user-select: none;
}

.chat-message.system {
  background: transparent;
  color: #888;
  font-style: italic;
  font-size: 12px;
  text-align: center;
  max-width: 100%;
  white-space: pre-line;
}

.chat-message.other {
  background: #252530;
  color: #e0e0e0;
  align-self: flex-start;
}

.chat-message.mine {
  background: rgba(212, 175, 55, 0.2);
  color: #e0e0e0;
  align-self: flex-end;
}

.chat-message.admin {
  background: rgba(239, 83, 80, 0.15);
  border: 1px solid rgba(239, 83, 80, 0.3);
  color: #ff6b6b;
  font-weight: 600;
  max-width: 100%;
}

.chat-message .nick {
  font-weight: 600;
  color: #d4af37;
  margin-right: 6px;
}

.chat-message.admin .nick {
  color: #ff6b6b;
}

.chat-message .msg-text {
  word-break: break-word;
}

.chat-message .msg-time {
  font-size: 10px;
  color: #666;
  margin-left: 8px;
  white-space: nowrap;
  align-self: flex-end;
}

.chat-message.mine .msg-time {
  color: #888;
}

.chat-input-area {
  padding: 10px;
  border-top: 1px solid #333;
  display: flex;
  gap: 8px;
}

.chat-input {
  flex: 1;
  background: #252530;
  border: 1px solid #333;
  border-radius: 6px;
  padding: 10px 12px;
  color: #e0e0e0;
  font-size: 16px;
  font-family: inherit;
  outline: none;
  min-height: 36px;
  max-height: 80px;
  resize: none;
  line-height: 1.4;
  overflow-y: auto;
}

.chat-input:focus {
  border-color: #d4af37;
}

.chat-input::placeholder {
  color: #666;
}

.chat-send-btn {
  background: linear-gradient(135deg, #d4af37, #b8962e);
  border: none;
  border-radius: 6px;
  padding: 10px 15px;
  color: #000;
  font-weight: 600;
  font-size: 13px;
  cursor: pointer;
  transition: opacity 0.2s;
}

.chat-send-btn:hover:not(:disabled) {
  opacity: 0.9;
}

.chat-send-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* ============================================================
    모바일 채팅 전체 화면 모달 (iOS 대응)
   - 문제 1: 채팅창 열면 배경(티커)이 어정쩡하게 노출됨
   - 문제 2: iOS에서 입력창 터치 시 자동 확대로 Send 버튼 잘림
   - 해결: 전체 화면 모달 + font-size 16px (iOS 확대 방지)
   ============================================================ */
@media (max-width: 768px) {
  /*  피드백 버튼: 모바일에서 위치 조정 */
  .feedback-btn {
    bottom: 75px;
    right: 15px;
    font-size: 11px;
    padding: 6px 12px;
  }
  
  /*  피드백 모달: 모바일 최적화 */
  .feedback-modal {
    width: 95%;
    max-height: 85vh;
  }
  
  .feedback-modal-body {
    padding: 15px;
  }
  
  .feedback-textarea {
    min-height: 100px;
  }
  
  /* 채팅 컨테이너: 모바일에서는 화면 하단 고정 */
  .chat-container {
    bottom: 15px;
    right: 15px;
  }
  
  /* 채팅창: 전체 화면 모달로 변경 */
  .chat-window {
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    right: 0 !important;
    bottom: 0 !important;
    width: 100% !important;
    height: 100% !important;
    height: 100dvh !important; /* Dynamic Viewport Height (iOS 대응) */
    max-width: 100% !important;
    max-height: 100% !important;
    border-radius: 0 !important; /* 둥근 모서리 제거 */
    z-index: 10000 !important; /* 최상단 노출 */
    border: none !important;
    background: #1a1a24 !important; /* 불투명 배경으로 티커 완전 가림 */
  }
  
  /* 채팅 헤더: 모바일 전체 화면에서 더 크게 + 우측 여백 증가 */
  .chat-window .chat-header {
    padding: 16px 20px 16px 15px; /* 우측 패딩 20px로 증가 */
    min-height: 50px;
  }
  
  /* 닫기 버튼: 터치하기 쉽게 크기 증가 (SVG 아이콘 대응) */
  .chat-window .chat-close-btn {
    padding: 8px;
    margin-right: -5px;
  }
  
  .chat-window .chat-close-icon {
    width: 42px;
    height: 42px;
  }
  
  /*  채팅 플로팅 버튼 아이콘: 모바일 크기 */
  .chat-toggle-icon {
    width: 22px;
    height: 22px;
  }
  
  /* 채팅 메시지 영역: 더 넓게 */
  .chat-window .chat-messages {
    flex: 1;
    padding: 12px;
    overflow-y: auto;
    -webkit-overflow-scrolling: touch; /* iOS 부드러운 스크롤 */
  }
  
  /* 입력 영역: 하단 고정, 키보드 위로 올라오도록 */
  .chat-window .chat-input-area {
    padding: 12px;
    padding-bottom: max(12px, env(safe-area-inset-bottom)); /* 아이폰 하단 안전 영역 */
    border-top: 1px solid #333;
    background: #1a1a24; /* 입력창 배경도 불투명 */
    display: flex;
    gap: 10px;
    box-sizing: border-box;
    width: 100%;
  }
  
  /* 입력창: iOS 자동 확대 방지 (font-size 16px 필수!) */
  .chat-window .chat-input {
    flex: 1;
    min-width: 0; /* flexbox에서 버튼 밀어내기 방지 */
    font-size: 16px !important; /* iOS 자동 확대 방지 핵심! */
    padding: 12px;
    border-radius: 8px;
    box-sizing: border-box;
  }
  
  /* 전송 버튼: 고정 너비로 잘림 방지 */
  .chat-window .chat-send-btn {
    flex-shrink: 0; /* 버튼 축소 방지 */
    min-width: 60px;
    padding: 12px 16px;
    font-size: 14px;
    border-radius: 8px;
  }
  
  /* [server262] 언어 토글 버튼 - 위치 미세 조정 */
  .lang-toggle-wrapper {
    top: 12px;
    right: 12px;
  }
  
  .lang-btn {
    padding: 4px 8px;
    font-size: 12px;
  }
}
</style>
</head>
<body>

<!--  언어 토글 버튼 -->
<div class="lang-toggle-wrapper">
  <button class="lang-btn" data-lang="ko" title="한국어">🇰🇷</button>
  <button class="lang-btn" data-lang="en" title="English">🇺🇸</button>
</div>

<div class="header">
  <h1>
    <svg class="header-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <!--  로켓 본체: 흰색 -->
      <path fill="#FFFFFF" d="M12 2C12 2 7 4 7 12c0 2.5.5 4.5 1 6h8c.5-1.5 1-3.5 1-6 0-8-5-10-5-10zm0 11c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/>
      <!--  날개: 골드 -->
      <path fill="#d4af37" d="M5 18c0-1.5.5-3 1-4l-3 1v3l2 2v-2zM19 18c0-1.5-.5-3-1-4l3 1v3l-2 2v-2z"/>
      <!--  불꽃: 골드 (애니메이션 적용) -->
      <path class="rocket-flame" fill="#FF9500" d="M9 18 L10 21 L10.5 19 L11 22 L12 19.5 L13 22 L13.5 19 L14 21 L15 18 Z"/>
    </svg>
    To The Moon List
    <span class="beta-badge" title="현재 베타 버전으로 운영 중입니다. 버그나 개선 의견은 화면 우측 하단의 의견 보내기 버튼을 통해 보내주시면 큰 도움이 됩니다." data-i18n-title="beta.tooltip">BETA</span>
  </h1>
  <p><span class="status-dot status-live"></span>실시간 코인 모멘텀 순위</p>
</div>

<div class="filters">
  <!--  다중 거래소 필터 - 2단 그룹 레이아웃 -->
  <div class="filter-group exchange-filter-group">
    <div class="exchange-group-wrapper" id="exchangeFilterGroup">
      <!-- Group 1: KRW 마켓 -->
      <div class="exchange-group">
        <span class="group-label">KRW 마켓</span>
        <div class="filter-left">
          <label class="filter-btn active" data-exchange-filter="UPBIT_SPOT">
            <input type="checkbox" checked>
            <span class="dot upbit"></span>업비트
          </label>
          <label class="filter-btn active" data-exchange-filter="BITHUMB_SPOT">
            <input type="checkbox" checked>
            <span class="dot bithumb"></span>빗썸
          </label>
        </div>
      </div>
      <!-- Group 2: USDT 마켓 -->
      <div class="exchange-group">
        <span class="group-label">USDT (글로벌)</span>
        <div class="filter-left">
          <label class="filter-btn active" data-exchange-filter="BINANCE_SPOT">
            <input type="checkbox" checked>
            <span class="dot binance"></span>바이낸스
          </label>
          <label class="filter-btn" data-exchange-filter="BINANCE_FUTURES">
            <input type="checkbox">
            <span class="dot binance futures"></span>바낸선물
          </label>
          <label class="filter-btn active" data-exchange-filter="OKX_SPOT">
            <input type="checkbox" checked>
            <span class="dot okx"></span>OKX
          </label>
          <label class="filter-btn" data-exchange-filter="OKX_FUTURES">
            <input type="checkbox">
            <span class="dot okx futures"></span>OKX선물
          </label>
        </div>
      </div>
    </div>
  </div>
  
  <!--  코인 검색창 -->
  <div class="filter-group search-filter-group">
    <div class="search-wrapper">
      <svg xmlns="http://www.w3.org/2000/svg" class="search-icon-svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="11" cy="11" r="8"></circle>
        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
      </svg>
      <input type="search" id="searchInput" placeholder="" autocomplete="off">
    </div>
  </div>
  
  <!--  통화 선택 필터 -->
  <div class="filter-group">
    <select id="currencyFilter" class="currency-select">
      <option value="ORIGINAL">기본 (거래소 통화)</option>
      <option value="KRW">₩ KRW (원화 환산)</option>
      <option value="USDT">₮ USDT (달러 환산)</option>
    </select>
  </div>
  
  <div class="filter-group">
    <select id="sortFilter">
      <option value="default">빠른 정렬 (초기화)</option>
      <option value="up" selected>상승확률 높은순</option>
      <option value="down">하락확률 높은순</option>
      <option value="change">24H 변동률순</option>
      <option value="symbol">코인 심볼순</option>
    </select>
  </div>
  
  <div class="filter-group view-toggle-group">
    <label>레이아웃</label>
    <div class="view-toggle-buttons">
      <button id="viewListOnlyBtn" class="view-btn">리스트만</button>
      <button id="viewWithChartBtn" class="view-btn active">차트 같이</button>
    </div>
  </div>
</div>

<!-- 메인 레이아웃 (명세서 3-3) -->
<div class="main-layout">
  <div id="coinListPanel">
    <!-- 모멘텀 기준 버튼 (수정 3: 리스트 패널 내부로 이동) -->
    <div class="momentum-section">
      <span class="momentum-section-label">모멘텀 기준</span>
      <div class="momentum-timeframe">
        <button class="momentum-btn active" data-unit="1">1분</button>
        <button class="momentum-btn" data-unit="3">3분</button>
        <button class="momentum-btn" data-unit="5">5분</button>
        <button class="momentum-btn disabled" data-unit="10" title="데이터 수집 중 (추후 오픈)">10분</button>
        <button class="momentum-btn" data-unit="15">15분</button>
        <button class="momentum-btn" data-unit="30">30분</button>
        <button class="momentum-btn" data-unit="60">1시간</button>
        <button class="momentum-btn" data-unit="240">4시간</button>
      </div>
    </div>
    <div class="coin-table-wrapper">
      <table>
        <thead>
          <tr>
            <th data-sort-key="exchange">거래소</th>
            <th data-sort-key="symbol">코인</th>
            <th data-sort-key="price">현재가</th>
            <th data-sort-key="change">24H</th>
            <th data-sort-key="up">상승%</th>
            <th data-sort-key="down">하락%</th>
          </tr>
        </thead>
        <tbody id="coinTableBody">
          <tr id="row-message"><td colspan="6" class="loading">데이터 로딩 중...</td></tr>
        </tbody>
      </table>
    </div>
  </div>
  
  <div id="resizer"></div>
  
  <div id="chartPanel">
    <div class="chart-placeholder" data-i18n="chart.selectCoin">
      좌측 테이블에서 코인을 선택하세요
    </div>
    <div id="tv-chart-container"></div>
    <div class="exchange-links" id="desktopTradeButtons"></div>
  </div>
</div>

<!-- 쿠키 동의 배너 (server118: 글로벌 표준 준수) -->
<div class="cookie-banner" id="cookieBanner">
  <div class="cookie-banner-content">
    <div class="cookie-banner-text">
      <span id="cookieBannerText">저희 사이트는 더 나은 사용성과 편의 기능을 제공하기 위해 쿠키를 사용합니다. 자세한 내용은 <a id="cookiePrivacyLink" style="color:#d4af37;text-decoration:underline;cursor:pointer;">개인정보처리방침</a>을 참고해 주세요.</span>
    </div>
    <div class="cookie-banner-buttons">
      <button class="cookie-btn cookie-btn-essential" id="cookieRejectBtn">모두 거부</button>
      <button class="cookie-btn cookie-btn-all" id="cookieAllBtn">모두 허용</button>
    </div>
  </div>
</div>

<div class="footer" id="mainFooter">
  <div class="footer-always-visible">
    <p class="warning">[WARN] 투자 참고 정보만 제공하며, 암호화폐는 원금 손실의 위험이 있습니다.</p>
  </div>

  <button id="footerToggleBtn" class="footer-toggle-btn" title="정보 더보기/접기">▼</button>

  <div id="footerCollapsible" class="footer-collapsible">
    <p>상승/하락 확률은 완성된 봉 기준으로 계산됩니다. 급격한 가격 변동 시 왜곡을 방지하기 위해 미완성 봉은 제외됩니다.</p>
    <p>빗썸 15분/4시간 모멘텀은 5분봉 데이터를 가공하여 산출되므로 실제 거래소 차트와 상이할 수 있습니다.</p>
    <div class="footer-links">
      <a onclick="openLegalModal('terms')">이용약관</a>
      <a onclick="openLegalModal('privacy')">개인정보처리방침</a>
      <a onclick="openLegalModal('disclaimer')">투자 유의사항</a>
    </div>
    <p>© 2025 To The Moon List. 실시간 데이터 제공: 업비트, 빗썸, 바이낸스, OKX</p>
  </div>
</div>

<!-- 모바일 전체화면 차트 모달 (명세서 5절) -->
<div class="mobile-chart-modal" id="mobileChartModal">
  <div class="mobile-chart-header">
    <div class="mobile-chart-title">
      <span class="symbol" id="mobileChartSymbol">BTC</span>
      <span class="exchange-tag" id="mobileChartExchange">업비트</span>
    </div>
    <button class="mobile-chart-close" id="mobileChartClose">&times;</button>
  </div>
  <div class="mobile-chart-body">
    <div id="mobile-tv-chart-container"></div>
    <div class="mobile-exchange-links" id="mobileTradeButtons"></div>
  </div>
</div>

<!-- 법적 고지 모달 (프론트 개선 3) -->
<div class="legal-modal-overlay" id="legalModalOverlay">
  <div class="legal-modal">
    <div class="legal-modal-header">
      <h3 id="legalModalTitle">제목</h3>
      <button class="legal-modal-close" onclick="closeLegalModal()">&times;</button>
    </div>
    <div class="legal-modal-body" id="legalModalBody">
      <!-- 내용이 JavaScript로 채워짐 -->
    </div>
  </div>
</div>

<!--  피드백 버튼 -->
<button class="feedback-btn" id="feedbackBtn" data-i18n="feedback.button">Feedback</button>

<!--  피드백 모달 -->
<div class="feedback-overlay" id="feedbackOverlay">
  <div class="feedback-modal">
    <div class="feedback-modal-header">
      <span class="feedback-modal-title" data-i18n="feedback.title">Send Feedback</span>
      <button class="feedback-modal-close" id="feedbackCloseBtn">&times;</button>
    </div>
    <div class="feedback-modal-body">
      <div class="feedback-form-group">
        <label class="feedback-label" data-i18n="feedback.category">Category</label>
        <select class="feedback-select" id="feedbackCategory">
          <option value="bug" data-i18n="feedback.categoryBug">Bug Report</option>
          <option value="feature" data-i18n="feedback.categoryFeature">Feature Request</option>
          <option value="other" data-i18n="feedback.categoryOther">Other</option>
        </select>
      </div>
      <div class="feedback-form-group">
        <label class="feedback-label" data-i18n="feedback.content">Content</label>
        <textarea class="feedback-textarea" id="feedbackContent" maxlength="2000" data-i18n-placeholder="feedback.contentPlaceholder" placeholder="Please describe in detail..."></textarea>
        <div class="feedback-char-count" id="feedbackCharCount">0 / 2000</div>
      </div>
      <div class="feedback-form-group">
        <label class="feedback-label" data-i18n="feedback.email">Email (optional)</label>
        <input type="email" class="feedback-input" id="feedbackEmail" data-i18n-placeholder="feedback.emailPlaceholder" placeholder="Enter your email if you want a reply">
      </div>
      <div id="feedbackStatus"></div>
    </div>
    <div class="feedback-modal-footer">
      <button class="feedback-cancel-btn" id="feedbackCancelBtn" data-i18n="feedback.cancel">Cancel</button>
      <button class="feedback-submit-btn" id="feedbackSubmitBtn" data-i18n="feedback.submit">Submit</button>
    </div>
  </div>
</div>

<!--  채팅 UI (우측 하단 말풍선) -->
<!--  닉네임 표시/변경 기능 추가 -->
<div class="chat-container" id="chatContainer">
  <div class="chat-window" id="chatWindow">
    <div class="chat-header">
      <span class="chat-header-title" data-i18n="chat.title">To The Moon Chat</span>
      <span class="chat-header-count" id="chatUserCount"></span>
      <button class="chat-close-btn" id="chatCloseBtn">
        <svg class="chat-close-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M7.41 8.59L12 13.17l4.59-4.58L18 10l-6 6-6-6 1.41-1.41z"/>
        </svg>
      </button>
    </div>
    <!--  닉네임 변경 영역 -->
    <div class="chat-nickname-bar">
      <span class="chat-nickname-label" data-i18n="chat.nickname">닉네임:</span>
      <span class="chat-nickname-value" id="chatNicknameLabel">Guest-0000</span>
      <button class="chat-nickname-edit-btn" id="chatNicknameEditBtn" data-i18n="chat.editNick">변경</button>
    </div>
    <div class="chat-messages" id="chatMessages"></div>
    <div class="chat-input-area">
      <textarea class="chat-input" id="chatInput" data-i18n-placeholder="chat.placeholder" placeholder="메시지를 입력하세요..." maxlength="500" rows="1"></textarea>
      <button class="chat-send-btn" id="chatSendBtn" data-i18n="chat.send">전송</button>
    </div>
  </div>
  <button class="chat-toggle-btn" id="chatToggleBtn" title="To The Moon Chat" aria-label="채팅 열기">
    <svg class="chat-toggle-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" focusable="false">
      <!--  둥근 흰색 말풍선 -->
      <path d="M12 3C6.5 3 2 6.58 2 11c0 2.13 1.02 4.07 2.68 5.5L4 20l4.35-2.18C9.53 18.27 10.74 18.5 12 18.5c5.5 0 10-3.58 10-7.5S17.5 3 12 3z" fill="#FFFFFF"/>
    </svg>
    <span class="chat-badge" id="chatBadge">0</span>
  </button>
  <!--  우클릭 컨텍스트 메뉴 -->
  <div id="chatContextMenu" class="chat-context-menu">
    <ul id="chatContextMenuList"></ul>
  </div>
</div>

<script>
// ---
//  SafeStorage - localStorage 예외 처리 래퍼
// - iOS 시크릿 모드에서 QuotaExceededError 방지
// - localStorage 사용 불가 환경에서도 앱 정상 동작 보장
// ---
var SafeStorage = {
  getItem: function(key) {
    try {
      return localStorage.getItem(key);
    } catch (e) {
      console.warn('[SafeStorage] getItem failed (Private Mode?):', e.message);
      return null;
    }
  },
  setItem: function(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch (e) {
      console.warn('[SafeStorage] setItem failed (Private Mode?):', e.message);
    }
  },
  removeItem: function(key) {
    try {
      localStorage.removeItem(key);
    } catch (e) {
      // ignore
    }
  }
};

// ---
// 전역 변수
// ---
var coins = [];
var selectedCoin = null;
var ws = null;
var currentMomentumTimeframe = 1;

// ════════════════════════════════════════════════════════════════
//  O(1) 코인 조회용 인덱스 맵
// - Key: "UPBIT_SPOT:BTC" 형식
// - Value: coins 배열의 인덱스
// - 효과: U 메시지 처리 시 O(N) 루프 → O(1) 직접 접근
// ════════════════════════════════════════════════════════════════
var coinIndexMap = {};
var filteredCoinIndexMap = {};

// ════════════════════════════════════════════════════════════════
//  검색 기능 전역 변수
// - searchKeyword: 현재 검색어 (공백 제거, 대문자 변환됨)
// ════════════════════════════════════════════════════════════════
var searchKeyword = '';

// ════════════════════════════════════════════════════════════════
//  즐겨찾기 전역 변수 및 함수
// - favoriteCoinsMap: 타임프레임별 즐겨찾기 Set
// - 구조: { "1": Set(["UPBIT:BTC", ...]), "3": Set(), ... }
// ════════════════════════════════════════════════════════════════
var favoriteCoinsMap = {};

// 즐겨찾기 초기화 (localStorage에서 복원)
function initFavorites() {
  // 타임프레임별 빈 Set 초기화
  var timeframes = [1, 3, 5, 15, 30, 60, 240];
  timeframes.forEach(function(tf) {
    favoriteCoinsMap[tf] = new Set();
  });
  
  // Cookie Consent 확인
  var consent = SafeStorage.getItem('cookieConsent');
  if (consent !== 'all') {
    console.log('[FAV] 쿠키 미동의 - 즐겨찾기 복원 스킵');
    return;
  }
  
  // localStorage에서 복원
  var saved = SafeStorage.getItem('fav_coins');
  if (saved) {
    try {
      var parsed = JSON.parse(saved);
      // 각 타임프레임별로 Set 복원
      for (var tf in parsed) {
        if (parsed.hasOwnProperty(tf) && Array.isArray(parsed[tf])) {
          favoriteCoinsMap[tf] = new Set(parsed[tf]);
        }
      }
      console.log('[FAV] 즐겨찾기 복원 완료:', JSON.stringify(parsed).substring(0, 100));
    } catch (e) {
      console.warn('[FAV] 즐겨찾기 복원 실패:', e.message);
    }
  }
}

// 즐겨찾기 저장 (localStorage에 저장)
function saveFavorites() {
  var consent = SafeStorage.getItem('cookieConsent');
  if (consent !== 'all') {
    console.log('[FAV] 쿠키 미동의 - 즐겨찾기 저장 스킵');
    return;
  }
  
  // Set을 Array로 변환하여 JSON 저장
  var toSave = {};
  for (var tf in favoriteCoinsMap) {
    if (favoriteCoinsMap.hasOwnProperty(tf)) {
      toSave[tf] = Array.from(favoriteCoinsMap[tf]);
    }
  }
  
  SafeStorage.setItem('fav_coins', JSON.stringify(toSave));
  console.log('[FAV] 즐겨찾기 저장 완료');
}

// 즐겨찾기 여부 확인
function isFavorite(exchange, symbol) {
  var tf = currentMomentumTimeframe;
  var key = exchange + ':' + symbol;
  return favoriteCoinsMap[tf] && favoriteCoinsMap[tf].has(key);
}

// 즐겨찾기 토글
function toggleFavorite(exchange, symbol) {
  var tf = currentMomentumTimeframe;
  var key = exchange + ':' + symbol;
  
  // Set이 없으면 생성
  if (!favoriteCoinsMap[tf]) {
    favoriteCoinsMap[tf] = new Set();
  }
  
  // 토글
  if (favoriteCoinsMap[tf].has(key)) {
    favoriteCoinsMap[tf].delete(key);
    console.log('[FAV] 즐겨찾기 해제: ' + key + ' (TF: ' + tf + ')');
  } else {
    favoriteCoinsMap[tf].add(key);
    console.log('[FAV] 즐겨찾기 등록: ' + key + ' (TF: ' + tf + ')');
  }
  
  // 저장 및 UI 갱신
  saveFavorites();
  renderTable();
}

//  마지막 렌더링 시 즐겨찾기 개수 (구분선 표시용)
var lastFavsCount = 0;

// ════════════════════════════════════════════════════════════════
//  Request ID 패턴 + Optimistic UI (Last Value Fallback)
// - tfRequestId: 매 TF 변경 요청마다 증가, stale response 필터링용
// - lastKnownMomentum: 마지막으로 알려진 모멘텀 값 저장 (정렬 유지용)
// ════════════════════════════════════════════════════════════════
var tfRequestId = 0;
var lastKnownMomentum = {}; // { 'BINANCE_SPOT:BTC': { up: 65.2, down: 34.8 }, ... }

// ════════════════════════════════════════════════════════════════
//  TF별 전체 데이터 캐싱 (Stale-While-Revalidate 패턴)
// - 탭 클릭 시 캐시 있으면 즉시 표시 → 서버 응답 기다리지 않음
// - 서버 응답 시 캐시 갱신 + 현재 TF일 때만 화면 갱신
// ════════════════════════════════════════════════════════════════
var tfDataCache = {
  1: null,    // 1분 데이터: { coins: [...], timestamp: Date.now() }
  3: null,    // 3분 데이터
  5: null,    // 5분 데이터
  15: null,   // 15분 데이터
  30: null,   // 30분 데이터
  60: null,   // 1시간 데이터
  240: null   // 4시간 데이터
};

// ════════════════════════════════════════════════════════════════
//  프리페칭 시스템 - 페이지 로딩 시 모든 TF 데이터 미리 로드
// ════════════════════════════════════════════════════════════════
var prefetchInProgress = false;  // 프리페칭 진행 중 플래그
var PREFETCH_DELAY = 1000;       // 초기 데이터 수신 후 프리페칭 시작까지 대기 (1초)

/**
 *  프리페칭 시작 - 모든 TF 데이터를 병렬로 미리 로드!
 * - 페이지 로딩 후 initial 데이터 수신 시 호출됨
 * - 현재 TF 제외하고 나머지 TF 데이터를 동시에 요청
 * - 효과: 1~3초 내 모든 TF 캐시 완료!
 */
function startPrefetching() {
  if (prefetchInProgress) {
    console.log('[Prefetch] 이미 진행 중, 스킵');
    return;
  }
  
  prefetchInProgress = true;
  var tfList = [1, 3, 5, 15, 30, 60, 240];
  var currentTf = currentMomentumTimeframe;
  var requestCount = 0;
  
  console.log('[Prefetch] 프리페칭 시작! 현재 TF=' + currentTf + '분 (병렬 요청)');
  
  // 모든 TF 동시 요청!
  tfList.forEach(function(tf) {
    // 현재 TF는 이미 있으므로 스킵
    if (tf === currentTf) {
      console.log('[Prefetch] ' + tf + '분 스킵 (현재 TF)');
      return;
    }
    
    // 이미 캐시에 있으면 스킵
    if (tfDataCache[tf] && tfDataCache[tf].coins && tfDataCache[tf].coins.length > 0) {
      console.log('[Prefetch] ' + tf + '분 스킵 (캐시 있음)');
      return;
    }
    
    // WebSocket으로 해당 TF 데이터 요청
    if (ws && ws.readyState === WebSocket.OPEN) {
      console.log('[Prefetch] ' + tf + '분 데이터 요청');
      requestCount++;
      
      ws.send(JSON.stringify({ 
        type: 'setTimeframe', 
        timeframe: tf,
        prefetch: true
      }));
    }
  });
  
  console.log('[Prefetch] 총 ' + requestCount + '개 TF 동시 요청 완료');
  
  // 프리페칭 완료 후 현재 TF로 복원 (3초 후 - 모든 응답 수신 예상 시간)
  setTimeout(function() {
    prefetchInProgress = false;
    restoreCurrentTimeframe();
    console.log('[Prefetch] 프리페칭 완료!');
  }, 3000);
}

/**
 *  프리페칭 완료 후 현재 TF로 복원
 * - 프리페칭 중 서버의 클라이언트 TF가 마지막 요청 TF로 남아있음
 * - 현재 TF로 다시 설정하여 브로드캐스트 수신 정상화
 */
function restoreCurrentTimeframe() {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ 
      type: 'setTimeframe', 
      timeframe: currentMomentumTimeframe
    }));
    console.log('[Prefetch] 현재 TF ' + currentMomentumTimeframe + '분으로 복원');
  }
}

var currentViewMode = 'with-chart';

// ---
//  다국어(i18n) 시스템
// ---
var currentLang = 'ko';

var i18n = {
  ko: {
    'meta.title': '실시간 코인 순위 | To The Moon List',
    'meta.description': '비트코인, 이더리움 등 200개 코인 실시간 시세와 급등 순위. 업비트, 빗썸, 바이낸스, OKX 거래소 지원.',
    'header.subtitle': '실시간 코인 순위',
    'filter.krwMarket': 'KRW 마켓',
    'filter.usdtMarket': 'USDT (글로벌)',
    'filter.upbit': '업비트',
    'filter.bithumb': '빗썸',
    'filter.binance': '바이낸스',
    'filter.binanceFutures': '바낸선물',
    'filter.okx': 'OKX',
    'filter.okxFutures': 'OKX선물',
    'filter.currency.original': '기본 (거래소 통화)',
    'filter.currency.krw': '₩ KRW (원화 환산)',
    'filter.currency.usdt': '₮ USDT (달러 환산)',
    'filter.sort.default': '빠른 정렬 (초기화)',
    'filter.sort.up': '상승확률 높은순',
    'filter.sort.down': '하락확률 높은순',
    'filter.sort.change': '24H 변동률순',
    'filter.sort.symbol': '코인 심볼순',
    'filter.layout': '레이아웃',
    'filter.listOnly': '리스트만',
    'filter.withChart': '차트 같이',
    'momentum.label': '모멘텀 기준',
    'momentum.1min': '1분',
    'momentum.3min': '3분',
    'momentum.5min': '5분',
    'momentum.10min': '10분',
    'momentum.15min': '15분',
    'momentum.30min': '30분',
    'momentum.1hour': '1시간',
    'momentum.4hour': '4시간',
    'table.exchange': '거래소',
    'table.coin': '코인',
    'table.price': '현재가',
    'table.change': '24H',
    'table.up': '상승%',
    'table.down': '하락%',
    'table.loading': '데이터 로딩 중...',
    'footer.warning': '투자 참고 정보만 제공하며, 암호화폐는 원금 손실의 위험이 있습니다.',
    'footer.info1': '상승/하락 확률은 완성된 봉 기준으로 계산됩니다. 급격한 가격 변동 시 왜곡을 방지하기 위해 미완성 봉은 제외됩니다.',
    'footer.info2': '빗썸 15분/4시간 모멘텀은 5분봉 데이터를 가공하여 산출되므로 실제 거래소 차트와 상이할 수 있습니다.',
    'footer.terms': '이용약관',
    'footer.privacy': '개인정보처리방침',
    'footer.disclaimer': '투자 유의사항',
    'footer.copyright': '© 2025 To The Moon List. 실시간 데이터 제공: 업비트, 빗썸, 바이낸스, OKX',
    'chart.selectCoin': '좌측 테이블에서 코인을 선택하세요',
    'chat.title': 'To The Moon Chat',
    'chat.placeholder': '메시지를 입력하세요...',
    'chat.send': '전송',
    'chat.welcome': 'To The Moon Chat에 오신 것을 환영합니다!\\n서로 배려하며 존중하는 대화를 부탁드립니다.',
    'chat.rateLimit': '메시지는 2초에 한 번만 보낼 수 있습니다.',
    'chat.nickname': '닉네임:',
    'chat.editNick': '변경',
    'chat.blockUser': '이 사용자 차단하기',
    'chat.deleteMyMsg': '내 메시지 삭제하기',
    'chat.confirmBlock': '이 사용자의 메시지를 모두 차단할까요?',
    'chat.confirmDelete': '이 메시지를 삭제할까요?',
    'chat.userBlocked': '사용자가 차단되었습니다.',
    'chat.deletedBySelf': '작성자가 메시지를 삭제했습니다.',
    'chat.deletedByAdmin': '관리자가 이 메시지의 표시를 중단했습니다.',
    'chat.adminModeEnabled': '관리자 모드가 활성화되었습니다.',
    'chat.adminHide': '이 메시지 숨기기',
    'chat.adminDelete': '이 메시지 삭제 (흔적 남김)',
    'chat.adminDeleteNoTrace': '이 메시지 삭제 (흔적 없이)',
    'chat.confirmAdminAction': '이 작업을 수행할까요?',
    'exchange.upbit': '업비트',
    'exchange.bithumb': '빗썸',
    'exchange.binance': '바이낸스',
    'exchange.binanceFutures': '바낸선물',
    'exchange.okx': 'OKX',
    'exchange.okxFutures': 'OKX선물',
    'cookie.text': '저희 사이트는 더 나은 사용성과 편의 기능을 제공하기 위해 쿠키를 사용합니다. 자세한 내용은 ',
    'cookie.privacyLink': '개인정보처리방침',
    'cookie.textEnd': '을 참고해 주세요.',
    'cookie.rejectAll': '모두 거부',
    'cookie.acceptAll': '모두 허용',
    'feedback.button': '의견 보내기',
    'feedback.title': '피드백 보내기',
    'feedback.category': '카테고리',
    'feedback.categoryBug': '버그 제보',
    'feedback.categoryFeature': '기능 제안',
    'feedback.categoryOther': '기타 의견',
    'feedback.content': '내용',
    'feedback.contentPlaceholder': '어떤 점이 불편하셨나요? 최대한 구체적으로 적어주시면 도움이 됩니다.',
    'feedback.email': '이메일 (선택)',
    'feedback.emailPlaceholder': '답변을 받길 원하시면 이메일을 적어 주세요.',
    'feedback.cancel': '취소',
    'feedback.submit': '보내기',
    'feedback.submitting': '전송 중...',
    'feedback.success': '피드백이 정상적으로 전송되었습니다. 소중한 의견 감사합니다.',
    'feedback.error': '전송 중 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.',
    'feedback.tooShort': '내용을 5자 이상 입력해 주세요.',
    'feedback.invalidEmail': '이메일 형식이 올바르지 않습니다.',
    'feedback.rateLimit': '잠시 후 다시 시도해 주세요.',
    'beta.tooltip': '현재 베타 버전으로 운영 중입니다. 버그나 개선 의견은 화면 우측 하단의 \"의견 보내기\" 버튼을 통해 보내주시면 큰 도움이 됩니다.',
    'search.placeholder': '심볼 검색 (예: BTC)',
    'search.noResults': '검색 결과가 없습니다.',
    'table.noData': '데이터 없음'
  },
  en: {
    'meta.title': 'Real-time Crypto Ranking | To The Moon List',
    'meta.description': 'Real-time prices and trending coins for 200+ cryptos. Upbit, Bithumb, Binance, OKX supported.',
    'header.subtitle': 'Real-time Crypto Ranking',
    'filter.krwMarket': 'KRW Market',
    'filter.usdtMarket': 'USDT (Global)',
    'filter.upbit': 'Upbit',
    'filter.bithumb': 'Bithumb',
    'filter.binance': 'Binance',
    'filter.binanceFutures': 'Binance Futures',
    'filter.okx': 'OKX',
    'filter.okxFutures': 'OKX Futures',
    'filter.currency.original': 'Default (Exchange Currency)',
    'filter.currency.krw': '₩ KRW (Korean Won)',
    'filter.currency.usdt': '₮ USDT (US Dollar)',
    'filter.sort.default': 'Quick Sort (Reset)',
    'filter.sort.up': 'Highest Bull %',
    'filter.sort.down': 'Highest Bear %',
    'filter.sort.change': '24H Change',
    'filter.sort.symbol': 'Symbol (A-Z)',
    'filter.layout': 'Layout',
    'filter.listOnly': 'List Only',
    'filter.withChart': 'With Chart',
    'momentum.label': 'Momentum',
    'momentum.1min': '1m',
    'momentum.3min': '3m',
    'momentum.5min': '5m',
    'momentum.10min': '10m',
    'momentum.15min': '15m',
    'momentum.30min': '30m',
    'momentum.1hour': '1H',
    'momentum.4hour': '4H',
    'table.exchange': 'Exchange',
    'table.coin': 'Coin',
    'table.price': 'Price',
    'table.change': '24H',
    'table.up': 'Bull %',
    'table.down': 'Bear %',
    'table.loading': 'Loading data...',
    'footer.warning': 'This service provides investment reference information only. Cryptocurrency investment involves the risk of losing principal.',
    'footer.info1': 'Up/Down probabilities are calculated based on completed candles. Incomplete candles are excluded to prevent distortion during rapid price changes.',
    'footer.info2': 'Bithumb 15min/4hour momentum is derived from 5-minute candle data and may differ from actual exchange charts.',
    'footer.terms': 'Terms of Service',
    'footer.privacy': 'Privacy Policy',
    'footer.disclaimer': 'Investment Disclaimer',
    'footer.copyright': '© 2025 To The Moon List. Real-time data: Upbit, Bithumb, Binance, OKX',
    'chart.selectCoin': 'Select a coin from the table on the left',
    'chat.title': 'To The Moon Chat',
    'chat.placeholder': 'Type a message...',
    'chat.send': 'Send',
    'chat.welcome': 'Welcome to To The Moon Chat!\\nPlease keep the conversation respectful and considerate.',
    'chat.rateLimit': 'You can only send a message once every 2 seconds.',
    'chat.nickname': 'Nickname:',
    'chat.editNick': 'Edit',
    'chat.blockUser': 'Block this user',
    'chat.deleteMyMsg': 'Delete my message',
    'chat.confirmBlock': 'Block all messages from this user?',
    'chat.confirmDelete': 'Delete this message?',
    'chat.userBlocked': 'User has been blocked.',
    'chat.deletedBySelf': 'This message was deleted by the author.',
    'chat.deletedByAdmin': 'This message has been hidden by admin.',
    'chat.adminModeEnabled': 'Admin mode enabled.',
    'chat.adminHide': 'Hide this message',
    'chat.adminDelete': 'Delete (leave trace)',
    'chat.adminDeleteNoTrace': 'Delete (no trace)',
    'chat.confirmAdminAction': 'Proceed with this action?',
    'exchange.upbit': 'Upbit',
    'exchange.bithumb': 'Bithumb',
    'exchange.binance': 'Binance',
    'exchange.binanceFutures': 'Binance F',
    'exchange.okx': 'OKX',
    'exchange.okxFutures': 'OKX F',
    'cookie.text': 'We use cookies to enhance usability and provide convenience features. For more details, please see our ',
    'cookie.privacyLink': 'Privacy Policy',
    'cookie.textEnd': '.',
    'cookie.rejectAll': 'Reject All',
    'cookie.acceptAll': 'Accept All',
    'feedback.button': 'Feedback',
    'feedback.title': 'Send Feedback',
    'feedback.category': 'Category',
    'feedback.categoryBug': 'Bug Report',
    'feedback.categoryFeature': 'Feature Request',
    'feedback.categoryOther': 'Other',
    'feedback.content': 'Content',
    'feedback.contentPlaceholder': 'What was inconvenient? Please describe in as much detail as possible.',
    'feedback.email': 'Email (optional)',
    'feedback.emailPlaceholder': 'Enter your email if you would like a reply.',
    'feedback.cancel': 'Cancel',
    'feedback.submit': 'Submit',
    'feedback.submitting': 'Submitting...',
    'feedback.success': 'Feedback submitted successfully. Thank you for your valuable input.',
    'feedback.error': 'An error occurred. Please try again later.',
    'feedback.tooShort': 'Please enter at least 5 characters.',
    'feedback.invalidEmail': 'Invalid email format.',
    'feedback.rateLimit': 'Please try again later.',
    'beta.tooltip': 'This service is currently in beta. Bug reports and suggestions are welcome via the \"Feedback\" button at the bottom-right.',
    'search.placeholder': 'Symbol search (e.g.: BTC)',
    'search.noResults': 'No search results.',
    'table.noData': 'No data'
  }
};

function t(key) {
  return i18n[currentLang][key] || i18n['ko'][key] || key;
}

function detectBrowserLanguage() {
  var lang = navigator.language || navigator.userLanguage || 'ko';
  return lang.toLowerCase().startsWith('ko') ? 'ko' : 'en';
}

function setLanguage(lang) {
  currentLang = lang;
  
  // 언어 버튼 active 상태 업데이트
  document.querySelectorAll('.lang-btn').forEach(function(btn) {
    btn.classList.toggle('active', btn.getAttribute('data-lang') === lang);
  });
  
  // HTML lang 속성 변경
  document.documentElement.lang = lang;
  
  //  메타 태그 동적 업데이트
  updateMetaTags(lang);
  
  // 정적 텍스트 업데이트
  applyTranslations();
}

//  메타 태그 업데이트 함수
function updateMetaTags(lang) {
  var title = t('meta.title');
  var description = t('meta.description');
  var locale = lang === 'ko' ? 'ko_KR' : 'en_US';
  
  // title 태그
  var pageTitle = document.getElementById('pageTitle');
  if (pageTitle) pageTitle.textContent = title;
  document.title = title;
  
  // meta description
  var metaDesc = document.getElementById('metaDescription');
  if (metaDesc) metaDesc.setAttribute('content', description);
  
  // Open Graph
  var ogTitle = document.getElementById('ogTitle');
  if (ogTitle) ogTitle.setAttribute('content', title);
  
  var ogDesc = document.getElementById('ogDescription');
  if (ogDesc) ogDesc.setAttribute('content', description);
  
  var ogLocale = document.getElementById('ogLocale');
  if (ogLocale) ogLocale.setAttribute('content', locale);
  
  // Twitter Card
  var twTitle = document.getElementById('twTitle');
  if (twTitle) twTitle.setAttribute('content', title);
  
  var twDesc = document.getElementById('twDescription');
  if (twDesc) twDesc.setAttribute('content', description);
}

function applyTranslations() {
  // 헤더 부제
  var headerSubtitle = document.querySelector('.header p');
  if (headerSubtitle) {
    var dot = headerSubtitle.querySelector('.status-dot');
    headerSubtitle.innerHTML = '';
    if (dot) headerSubtitle.appendChild(dot);
    headerSubtitle.appendChild(document.createTextNode(t('header.subtitle')));
  }
  
  // KRW/USDT 마켓 라벨
  var groupLabels = document.querySelectorAll('.group-label');
  if (groupLabels[0]) groupLabels[0].textContent = t('filter.krwMarket');
  if (groupLabels[1]) groupLabels[1].textContent = t('filter.usdtMarket');
  
  // 거래소 필터 버튼
  var exchangeMap = {
    'UPBIT_SPOT': 'filter.upbit',
    'BITHUMB_SPOT': 'filter.bithumb',
    'BINANCE_SPOT': 'filter.binance',
    'BINANCE_FUTURES': 'filter.binanceFutures',
    'OKX_SPOT': 'filter.okx',
    'OKX_FUTURES': 'filter.okxFutures'
  };
  document.querySelectorAll('[data-exchange-filter]').forEach(function(el) {
    var key = exchangeMap[el.getAttribute('data-exchange-filter')];
    if (key) {
      var dot = el.querySelector('.dot');
      var checkbox = el.querySelector('input');
      el.innerHTML = '';
      if (checkbox) el.appendChild(checkbox);
      if (dot) el.appendChild(dot);
      el.appendChild(document.createTextNode(t(key)));
    }
  });
  
  // 통화 선택
  var currencySelect = document.getElementById('currencyFilter');
  if (currencySelect) {
    currencySelect.options[0].text = t('filter.currency.original');
    currencySelect.options[1].text = t('filter.currency.krw');
    currencySelect.options[2].text = t('filter.currency.usdt');
  }
  
  // 정렬 선택
  var sortSelect = document.getElementById('sortFilter');
  if (sortSelect) {
    sortSelect.options[0].text = t('filter.sort.default');
    sortSelect.options[1].text = t('filter.sort.up');
    sortSelect.options[2].text = t('filter.sort.down');
    sortSelect.options[3].text = t('filter.sort.change');
    sortSelect.options[4].text = t('filter.sort.symbol');
  }
  
  // 레이아웃
  var layoutLabel = document.querySelector('.view-toggle-group label');
  if (layoutLabel) layoutLabel.textContent = t('filter.layout');
  var listOnlyBtn = document.getElementById('viewListOnlyBtn');
  var withChartBtn = document.getElementById('viewWithChartBtn');
  if (listOnlyBtn) listOnlyBtn.textContent = t('filter.listOnly');
  if (withChartBtn) withChartBtn.textContent = t('filter.withChart');
  
  // 모멘텀 라벨
  var momLabel = document.querySelector('.momentum-section-label');
  if (momLabel) momLabel.textContent = t('momentum.label');
  
  // 모멘텀 버튼
  var momBtns = document.querySelectorAll('.momentum-btn');
  var momMap = {'1':'1min','3':'3min','5':'5min','10':'10min','15':'15min','30':'30min','60':'1hour','240':'4hour'};
  momBtns.forEach(function(btn) {
    var unit = btn.getAttribute('data-unit');
    if (momMap[unit]) btn.textContent = t('momentum.' + momMap[unit]);
  });
  
  // 테이블 헤더
  var thMap = {'exchange':'table.exchange','symbol':'table.coin','price':'table.price','change':'table.change','up':'table.up','down':'table.down'};
  document.querySelectorAll('th[data-sort-key]').forEach(function(th) {
    var key = th.getAttribute('data-sort-key');
    if (thMap[key]) th.textContent = t(thMap[key]);
  });
  
  // 로딩 메시지
  var loadingTd = document.querySelector('#row-message td');
  if (loadingTd && loadingTd.classList.contains('loading')) {
    loadingTd.textContent = t('table.loading');
  }
  
  // 푸터
  var footerWarning = document.querySelector('.footer-always-visible .warning');
  if (footerWarning) footerWarning.textContent = t('footer.warning');
  
  var footerInfo = document.querySelectorAll('.footer-collapsible > p');
  if (footerInfo[0]) footerInfo[0].textContent = t('footer.info1');
  if (footerInfo[1]) footerInfo[1].textContent = t('footer.info2');
  if (footerInfo[2]) footerInfo[2].textContent = t('footer.copyright');
  
  var footerLinks = document.querySelectorAll('.footer-links a');
  if (footerLinks[0]) footerLinks[0].textContent = t('footer.terms');
  if (footerLinks[1]) footerLinks[1].textContent = t('footer.privacy');
  if (footerLinks[2]) footerLinks[2].textContent = t('footer.disclaimer');
  
  // 채팅
  var chatTitle = document.querySelector('.chat-header-title');
  if (chatTitle) chatTitle.textContent = t('chat.title');
  var chatInput = document.getElementById('chatInput');
  if (chatInput) chatInput.placeholder = t('chat.placeholder');
  var chatSendBtn = document.getElementById('chatSendBtn');
  if (chatSendBtn) chatSendBtn.textContent = t('chat.send');
  
  //  닉네임 라벨 텍스트 업데이트
  var chatNickLabel = document.querySelector('.chat-nickname-label');
  if (chatNickLabel) chatNickLabel.textContent = t('chat.nickname');
  var chatNickEditBtn = document.getElementById('chatNicknameEditBtn');
  if (chatNickEditBtn) chatNickEditBtn.textContent = t('chat.editNick');
  
  //  data-i18n 속성을 가진 모든 요소 번역
  document.querySelectorAll('[data-i18n]').forEach(function(el) {
    var key = el.getAttribute('data-i18n');
    if (key) el.textContent = t(key);
  });
  
  //  테이블 내 거래소명 재렌더링 (언어 변경 시)
  if (typeof renderTable === 'function' && coins && coins.length > 0) {
    renderTable();
  }
  
  //  거래 버튼 재렌더링 (언어 변경 시)
  if (currentSymbol && currentExchangeId) {
    if (typeof updateTradeButtons === 'function') {
      updateTradeButtons(currentSymbol, currentExchangeId);
    }
    if (typeof updateMobileTradeButtons === 'function') {
      updateMobileTradeButtons(currentSymbol, currentExchangeId);
    }
  }
  
  //  쿠키 배너 언어 업데이트
  if (typeof updateCookieBannerLanguage === 'function') {
    updateCookieBannerLanguage();
  }
  
  //  BETA 뱃지 툴팁 업데이트
  var betaBadge = document.querySelector('.beta-badge');
  if (betaBadge) betaBadge.setAttribute('title', t('beta.tooltip'));
  
  //  검색창 placeholder 업데이트
  var searchInput = document.getElementById('searchInput');
  if (searchInput) searchInput.setAttribute('placeholder', t('search.placeholder'));
}

// ---
//  채팅 시스템 변수
//  myClientId 추가 - 내 메시지 식별용
//  blockedSenders 추가 - 차단 리스트
//  chatAdminMode 추가 - 관리자 모드 플래그
// ---
var chatNickname = null;
var chatLastSentTime = 0;
var chatUnreadCount = 0;
var chatWindowOpen = false;
var myClientId = null;  //  서버에서 받은 내 clientId
var blockedSenders = [];  //  차단된 발신자 목록
var chatAdminMode = false;  //  관리자 모드 활성화 여부

//  차단 리스트 로드 (페이지 로드 시)
(function loadBlockedSenders() {
  try {
    var stored = SafeStorage.getItem('chatBlockedSenders');
    if (stored) {
      blockedSenders = JSON.parse(stored);
      if (!Array.isArray(blockedSenders)) {
        blockedSenders = [];
      }
    }
  } catch (e) {
    blockedSenders = [];
  }
})();

//  차단된 발신자인지 확인
function isBlockedSender(msg) {
  if (!msg || blockedSenders.length === 0) return false;
  
  for (var i = 0; i < blockedSenders.length; i++) {
    var item = blockedSenders[i];
    // clientId 또는 ipTag가 일치하면 차단
    if ((item.clientId && msg.clientId && item.clientId === msg.clientId) ||
        (item.ipTag && msg.ipTag && item.ipTag === msg.ipTag)) {
      return true;
    }
  }
  return false;
}

//  발신자 차단 등록
function blockSender(msg) {
  var entry = {
    clientId: msg.clientId || null,
    ipTag: msg.ipTag || null,
    nick: msg.nick || null,  // 참고용 닉네임
    blockedAt: Date.now()
  };
  blockedSenders.push(entry);
  SafeStorage.setItem('chatBlockedSenders', JSON.stringify(blockedSenders));
  
  // 현재 화면에 있는 동일 발신자 메시지 모두 숨김
  hideBlockedMessages(entry);
}

//  차단된 메시지 숨기기
function hideBlockedMessages(entry) {
  var messages = document.querySelectorAll('.chat-message');
  messages.forEach(function(div) {
    var divClientId = div.dataset.clientId;
    var divIpTag = div.dataset.ipTag;
    
    if ((entry.clientId && divClientId && entry.clientId === divClientId) ||
        (entry.ipTag && divIpTag && entry.ipTag === divIpTag)) {
      div.style.display = 'none';
    }
  });
}

//  컨텍스트 메뉴 열기
function openChatContextMenu(e, msg, div) {
  var menu = document.getElementById('chatContextMenu');
  var ul = document.getElementById('chatContextMenuList');
  if (!menu || !ul) return;
  
  // 메뉴 내용 초기화
  ul.innerHTML = '';
  
  // 내 메시지인지 확인
  var selfMsg = (msg.clientId && myClientId && msg.clientId === myClientId);
  
  if (selfMsg) {
    // 내 메시지: 삭제하기 옵션
    var li = document.createElement('li');
    li.className = 'danger';
    li.innerHTML = '<span>' + t('chat.deleteMyMsg') + '</span>';
    li.onclick = function() {
      closeChatContextMenu();
      if (confirm(t('chat.confirmDelete'))) {
        //  서버에 삭제 요청 (전체 사용자에게서 숨김)
        if (ws && ws.readyState === WebSocket.OPEN && msg.id) {
          ws.send(JSON.stringify({
            type: 'chat_moderation',
            action: 'self_delete',
            messageId: msg.id
          }));
          console.log('[Chat] 메시지 삭제 요청:', msg.id);
        } else {
          // WebSocket 연결 안 됨 - 로컬에서만 숨김
          div.style.display = 'none';
          console.log('[Chat] WS 미연결, 로컬 숨김만:', msg.id);
        }
      }
    };
    ul.appendChild(li);
  } else {
    // 타인 메시지: 차단하기 옵션
    var li = document.createElement('li');
    li.className = 'danger';
    li.innerHTML = '<span>' + t('chat.blockUser') + '</span>';
    li.onclick = function() {
      closeChatContextMenu();
      if (confirm(t('chat.confirmBlock'))) {
        blockSender(msg);
        // 시스템 메시지로 알림
        addChatMessage({
          type: 'system',
          text: t('chat.userBlocked')
        }, true);
      }
    };
    ul.appendChild(li);
  }
  
  //  관리자 모드 옵션 추가
  if (chatAdminMode && !selfMsg) {
    // 구분선
    var separator = document.createElement('li');
    separator.style.borderTop = '1px solid #444';
    separator.style.margin = '4px 0';
    separator.style.padding = '0';
    separator.style.pointerEvents = 'none';
    ul.appendChild(separator);
    
    // 관리자 숨기기
    var liHide = document.createElement('li');
    liHide.innerHTML = '<span>' + t('chat.adminHide') + '</span>';
    liHide.onclick = function() {
      closeChatContextMenu();
      if (confirm(t('chat.confirmAdminAction'))) {
        if (ws && ws.readyState === WebSocket.OPEN && msg.id) {
          ws.send(JSON.stringify({
            type: 'chat_moderation',
            action: 'admin_hide',
            messageId: msg.id
          }));
          console.log('[Admin] 메시지 숨김 요청:', msg.id);
        }
      }
    };
    ul.appendChild(liHide);
    
    // 관리자 삭제 (흔적 남김)
    var liDelete = document.createElement('li');
    liDelete.className = 'danger';
    liDelete.innerHTML = '<span>' + t('chat.adminDelete') + '</span>';
    liDelete.onclick = function() {
      closeChatContextMenu();
      if (confirm(t('chat.confirmAdminAction'))) {
        if (ws && ws.readyState === WebSocket.OPEN && msg.id) {
          ws.send(JSON.stringify({
            type: 'chat_moderation',
            action: 'admin_delete',
            messageId: msg.id,
            noTrace: false
          }));
          console.log('[Admin] 메시지 삭제 요청 (흔적 남김):', msg.id);
        }
      }
    };
    ul.appendChild(liDelete);
    
    // 관리자 삭제 (흔적 없이)
    var liDeleteNoTrace = document.createElement('li');
    liDeleteNoTrace.className = 'danger';
    liDeleteNoTrace.innerHTML = '<span>' + t('chat.adminDeleteNoTrace') + '</span>';
    liDeleteNoTrace.onclick = function() {
      closeChatContextMenu();
      if (confirm(t('chat.confirmAdminAction'))) {
        if (ws && ws.readyState === WebSocket.OPEN && msg.id) {
          ws.send(JSON.stringify({
            type: 'chat_moderation',
            action: 'admin_delete',
            messageId: msg.id,
            noTrace: true
          }));
          console.log('[Admin] 메시지 삭제 요청 (흔적 없이):', msg.id);
        }
      }
    };
    ul.appendChild(liDeleteNoTrace);
  }
  
  // 메뉴 위치 계산 (화면 밖으로 나가지 않도록)
  menu.style.display = 'block';
  
  var menuWidth = menu.offsetWidth;
  var menuHeight = menu.offsetHeight;
  var windowWidth = window.innerWidth;
  var windowHeight = window.innerHeight;
  
  var posX = e.clientX;
  var posY = e.clientY;
  
  // 오른쪽 경계 체크
  if (posX + menuWidth > windowWidth - 10) {
    posX = windowWidth - menuWidth - 10;
  }
  
  // 하단 경계 체크
  if (posY + menuHeight > windowHeight - 10) {
    posY = windowHeight - menuHeight - 10;
  }
  
  menu.style.left = posX + 'px';
  menu.style.top = posY + 'px';
}

//  컨텍스트 메뉴 닫기
function closeChatContextMenu() {
  var menu = document.getElementById('chatContextMenu');
  if (menu) {
    menu.style.display = 'none';
  }
}

//  문서 클릭 시 컨텍스트 메뉴 닫기
document.addEventListener('click', function(e) {
  var menu = document.getElementById('chatContextMenu');
  if (menu && menu.style.display === 'block') {
    // 메뉴 외부 클릭 시 닫기
    if (!menu.contains(e.target)) {
      closeChatContextMenu();
    }
  }
});

//  ESC 키로 컨텍스트 메뉴 닫기
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    closeChatContextMenu();
  }
});

// ---
//  피드백 초기화
// ---
function initFeedback() {
  var feedbackBtn = document.getElementById('feedbackBtn');
  var feedbackOverlay = document.getElementById('feedbackOverlay');
  var feedbackCloseBtn = document.getElementById('feedbackCloseBtn');
  var feedbackCancelBtn = document.getElementById('feedbackCancelBtn');
  var feedbackSubmitBtn = document.getElementById('feedbackSubmitBtn');
  var feedbackCategory = document.getElementById('feedbackCategory');
  var feedbackContent = document.getElementById('feedbackContent');
  var feedbackEmail = document.getElementById('feedbackEmail');
  var feedbackCharCount = document.getElementById('feedbackCharCount');
  var feedbackStatus = document.getElementById('feedbackStatus');
  
  if (!feedbackBtn || !feedbackOverlay) return;
  
  // 모달 열기
  feedbackBtn.addEventListener('click', function() {
    feedbackOverlay.classList.add('open');
    feedbackStatus.innerHTML = '';
    feedbackStatus.className = '';
  });
  
  // 모달 닫기
  function closeFeedbackModal() {
    feedbackOverlay.classList.remove('open');
  }
  
  feedbackCloseBtn.addEventListener('click', closeFeedbackModal);
  feedbackCancelBtn.addEventListener('click', closeFeedbackModal);
  
  // 오버레이 클릭으로 닫기
  feedbackOverlay.addEventListener('click', function(e) {
    if (e.target === feedbackOverlay) {
      closeFeedbackModal();
    }
  });
  
  // ESC 키로 닫기
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && feedbackOverlay.classList.contains('open')) {
      closeFeedbackModal();
    }
  });
  
  // 글자수 카운트
  feedbackContent.addEventListener('input', function() {
    var len = feedbackContent.value.length;
    feedbackCharCount.textContent = len + ' / 2000';
    if (len > 1800) {
      feedbackCharCount.classList.add('warning');
    } else {
      feedbackCharCount.classList.remove('warning');
    }
  });
  
  // 이메일 형식 검증
  function isValidEmail(email) {
    if (!email || email.trim() === '') return true;
    return /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email);
  }
  
  // 피드백 제출
  feedbackSubmitBtn.addEventListener('click', function() {
    var category = feedbackCategory.value;
    var content = feedbackContent.value.trim();
    var email = feedbackEmail.value.trim();
    
    // 검증
    if (content.length < 5) {
      feedbackStatus.className = 'feedback-status error';
      feedbackStatus.textContent = t('feedback.tooShort');
      return;
    }
    
    if (email && !isValidEmail(email)) {
      feedbackStatus.className = 'feedback-status error';
      feedbackStatus.textContent = t('feedback.invalidEmail');
      return;
    }
    
    // 제출 시작
    feedbackSubmitBtn.disabled = true;
    feedbackSubmitBtn.textContent = t('feedback.submitting');
    feedbackStatus.innerHTML = '';
    feedbackStatus.className = '';
    
    // API 요청
    var payload = {
      pagePath: window.location.pathname,
      category: category,
      content: content,
      email: email,
      userAgent: navigator.userAgent,
      referrer: document.referrer,
      ts: Date.now()
    };
    
    fetch('/api/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
    .then(function(res) {
      return res.json().then(function(data) {
        return { status: res.status, data: data };
      });
    })
    .then(function(result) {
      feedbackSubmitBtn.disabled = false;
      feedbackSubmitBtn.textContent = t('feedback.submit');
      
      if (result.status === 200 && result.data.ok) {
        feedbackStatus.className = 'feedback-status success';
        feedbackStatus.textContent = t('feedback.success');
        // 2초 후 모달 닫기
        setTimeout(function() {
          closeFeedbackModal();
          // 폼 리셋
          feedbackContent.value = '';
          feedbackEmail.value = '';
          feedbackCategory.selectedIndex = 0;
          feedbackCharCount.textContent = '0 / 2000';
          feedbackCharCount.classList.remove('warning');
        }, 2000);
      } else if (result.status === 429) {
        feedbackStatus.className = 'feedback-status error';
        feedbackStatus.textContent = t('feedback.rateLimit');
      } else {
        feedbackStatus.className = 'feedback-status error';
        feedbackStatus.textContent = t('feedback.error');
      }
    })
    .catch(function(err) {
      console.error('[FEEDBACK] Submit error:', err);
      feedbackSubmitBtn.disabled = false;
      feedbackSubmitBtn.textContent = t('feedback.submit');
      feedbackStatus.className = 'feedback-status error';
      feedbackStatus.textContent = t('feedback.error');
    });
  });
}

function generateNickname() {
  var stored = SafeStorage.getItem('chatNick');
  if (stored) return stored;
  var num = Math.floor(1000 + Math.random() * 9000);
  var nick = 'Guest-' + num;
  SafeStorage.setItem('chatNick', nick);
  return nick;
}

function initChat() {
  chatNickname = generateNickname();
  
  var chatToggleBtn = document.getElementById('chatToggleBtn');
  var chatCloseBtn = document.getElementById('chatCloseBtn');
  var chatWindow = document.getElementById('chatWindow');
  var chatInput = document.getElementById('chatInput');
  var chatSendBtn = document.getElementById('chatSendBtn');
  var langToggleWrapper = document.querySelector('.lang-toggle-wrapper'); //  언어 버튼 요소
  
  //  닉네임 UI 초기화
  var chatNicknameLabel = document.getElementById('chatNicknameLabel');
  var chatNicknameEditBtn = document.getElementById('chatNicknameEditBtn');
  
  if (chatNicknameLabel) {
    chatNicknameLabel.textContent = chatNickname;
  }
  
  //  닉네임 변경 버튼 이벤트
  if (chatNicknameEditBtn) {
    chatNicknameEditBtn.addEventListener('click', function() {
      var promptMsg = currentLang === 'ko' 
        ? '새 닉네임을 입력하세요 (2~16자):' 
        : 'Enter new nickname (2-16 characters):';
      var newNick = prompt(promptMsg, chatNickname);
      
      if (newNick === null) return; // 취소
      
      newNick = newNick.trim();
      
      // 유효성 검사
      if (newNick.length < 2 || newNick.length > 16) {
        var errorMsg = currentLang === 'ko' 
          ? '닉네임은 2~16자여야 합니다.' 
          : 'Nickname must be 2-16 characters.';
        alert(errorMsg);
        return;
      }
      
      // XSS 방지를 위한 특수문자 제거 (알파벳, 숫자, 한글, -, _ 만 허용)
      newNick = newNick.replace(/[^a-zA-Z0-9가-힣ㄱ-ㅎㅏ-ㅣ_-]/g, '');
      
      if (newNick.length < 2) {
        var errorMsg2 = currentLang === 'ko' 
          ? '허용되지 않는 문자가 포함되어 있습니다.' 
          : 'Contains invalid characters.';
        alert(errorMsg2);
        return;
      }
      
      // 닉네임 업데이트
      chatNickname = newNick;
      SafeStorage.setItem('chatNick', newNick);
      if (chatNicknameLabel) {
        chatNicknameLabel.textContent = newNick;
      }
      
      var successMsg = currentLang === 'ko' 
        ? '닉네임이 변경되었습니다: ' + newNick 
        : 'Nickname changed to: ' + newNick;
      addChatMessage({ type: 'system', text: successMsg });
    });
  }
  
  // 토글 버튼
  chatToggleBtn.addEventListener('click', function() {
    chatWindowOpen = !chatWindowOpen;
    chatWindow.classList.toggle('open', chatWindowOpen);
    if (chatWindowOpen) {
      chatUnreadCount = 0;
      updateChatBadge();
      chatInput.focus();
      
      //  채팅창 열릴 때 언어 버튼 숨김 (모바일 간섭 방지)
      if (langToggleWrapper) {
        langToggleWrapper.style.display = 'none';
      }
    } else {
      //  채팅창 닫힐 때 언어 버튼 복구
      if (langToggleWrapper) {
        langToggleWrapper.style.display = 'flex';
      }
    }
  });
  
  // 닫기 버튼
  chatCloseBtn.addEventListener('click', function() {
    chatWindowOpen = false;
    chatWindow.classList.remove('open');
    
    //  채팅창 닫힐 때 언어 버튼 복구
    if (langToggleWrapper) {
      langToggleWrapper.style.display = 'flex';
    }
  });
  
  // 전송 버튼
  chatSendBtn.addEventListener('click', sendChatMessage);
  
  //  Enter/Shift+Enter 키 처리
  // PC: Enter=전송, Shift+Enter=줄바꿈
  // 모바일: Enter=줄바꿈 (전송은 버튼으로)
  chatInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
      if (!e.shiftKey && !isMobile()) {
        e.preventDefault();
        sendChatMessage();
      }
      // Shift+Enter 또는 모바일 Enter: 기본 동작(줄바꿈) 허용
    }
  });
  
  //  textarea 자동 높이 조절
  function autoResizeChatInput() {
    chatInput.style.height = 'auto';
    chatInput.style.height = Math.min(chatInput.scrollHeight, 80) + 'px';
  }
  chatInput.addEventListener('input', autoResizeChatInput);
  
  // 환영 메시지 (로컬)
  addChatMessage({ type: 'system', text: t('chat.welcome') });
  
  // [iOS Fix] 모바일에서 채팅 입력 시 키보드 공간 확보를 위해 푸터 숨김 처리
  if (isMobile()) {
    var footerEl = document.getElementById('mainFooter');
    
    chatInput.addEventListener('focus', function() {
      if (footerEl) footerEl.style.display = 'none';
    });

    chatInput.addEventListener('blur', function() {
      if (footerEl) footerEl.style.display = 'block';
    });
  }
}

function sendChatMessage() {
  var chatInput = document.getElementById('chatInput');
  var chatSendBtn = document.getElementById('chatSendBtn');
  var text = chatInput.value.trim();
  
  if (!text) return;
  
  // 도배 방지 (2초)
  var now = Date.now();
  if (now - chatLastSentTime < 2000) {
    alert(t('chat.rateLimit'));
    return;
  }
  
  // WebSocket으로 전송
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: 'chat',
      nick: chatNickname,
      text: text
    }));
    
    chatLastSentTime = now;
    chatInput.value = '';
    chatInput.style.height = 'auto';
    
    // 버튼 비활성화 (2초)
    chatSendBtn.disabled = true;
    setTimeout(function() {
      chatSendBtn.disabled = false;
    }, 2000);
  }
}

function addChatMessage(msg, skipBadge) {
  //  차단된 발신자의 메시지는 표시하지 않음
  if (msg.type === 'chat' && isBlockedSender(msg)) {
    return;
  }
  
  var chatMessages = document.getElementById('chatMessages');
  var div = document.createElement('div');
  div.className = 'chat-message';
  
  //  메타데이터 저장 (data-* 속성)
  div.dataset.msgId = msg.id || '';
  div.dataset.clientId = msg.clientId || '';
  div.dataset.ipTag = msg.ipTag || '';
  
  // 시간 표시 (현지 시간대 기준)
  var timeStr = '';
  if (msg.timestamp) {
    var date = new Date(msg.timestamp);
    var hours = date.getHours().toString().padStart(2, '0');
    var minutes = date.getMinutes().toString().padStart(2, '0');
    timeStr = hours + ':' + minutes;
  }
  
  //  삭제된 메시지 처리 (히스토리에서 로드 시)
  if (msg.deleted && msg.stubText) {
    div.classList.add('chat-message-deleted');
    div.innerHTML = '<span class="deleted-stub">' + escapeHtml(msg.stubText) + '</span>';
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    return;  // 삭제된 메시지는 추가 처리 없이 종료
  }
  
  if (msg.type === 'system') {
    div.classList.add('system');
    div.textContent = msg.text;
  } else if (msg.type === 'admin') {
    div.classList.add('admin');
    var timeHtml = timeStr ? '<span class="msg-time">' + timeStr + '</span>' : '';
    div.innerHTML = '<span class="nick">[' + (currentLang === 'ko' ? '공지' : 'Notice') + ']</span>' + 
                    '<span class="msg-text">' + escapeHtml(msg.text) + '</span>' + timeHtml;
  } else if (msg.type === 'chat') {
    var isMine = msg.nick === chatNickname;
    div.classList.add(isMine ? 'mine' : 'other');
    var timeHtml = timeStr ? '<span class="msg-time">' + timeStr + '</span>' : '';
    if (!isMine) {
      div.innerHTML = '<span class="nick">' + escapeHtml(msg.nick) + '</span>' + 
                      '<span class="msg-text">' + escapeHtml(msg.text) + '</span>' + timeHtml;
    } else {
      div.innerHTML = '<span class="msg-text">' + escapeHtml(msg.text) + '</span>' + timeHtml;
    }
    
    //  우클릭 컨텍스트 메뉴 이벤트 등록 (채팅 메시지만)
    div.addEventListener('contextmenu', function(e) {
      e.preventDefault();
      openChatContextMenu(e, msg, div);
    });
    
    //  모바일 롱프레스 -> 컨텍스트 메뉴 열기 (고도화)
    if (isMobile()) {
      var longPressTimer = null;
      var longPressActivated = false;
      var LONG_PRESS_MS = 2500; // 2.5초
      
      function startLongPress(e) {
        if (!e.touches || e.touches.length !== 1) return;
        
        // 텍스트 선택/복사 기본 동작 선제 차단
        e.preventDefault();
        
        var touch = e.touches[0];
        var startX = touch.clientX;
        var startY = touch.clientY;
        
        longPressActivated = false;
        longPressTimer = setTimeout(function() {
          longPressActivated = true;
          openChatContextMenu({ clientX: startX, clientY: startY }, msg, div);
        }, LONG_PRESS_MS);
      }
      
      function cancelLongPress(e) {
        if (longPressTimer !== null) {
          clearTimeout(longPressTimer);
          longPressTimer = null;
        }
        // 롱프레스 성공 후에는 탭 이벤트 방지
        if (longPressActivated) {
          e.preventDefault();
          longPressActivated = false;
        }
      }
      
      div.addEventListener('touchstart', startLongPress, { passive: false });
      div.addEventListener('touchend', cancelLongPress);
      div.addEventListener('touchmove', cancelLongPress);
      div.addEventListener('touchcancel', cancelLongPress);
    }
  }
  
  chatMessages.appendChild(div);
  chatMessages.scrollTop = chatMessages.scrollHeight;
  
  // 배지 업데이트 (히스토리 로드 시에는 스킵)
  if (!skipBadge && !chatWindowOpen && msg.type !== 'system' && msg.nick !== chatNickname) {
    chatUnreadCount++;
    updateChatBadge();
  }
}

function updateChatBadge() {
  var badge = document.getElementById('chatBadge');
  if (chatUnreadCount > 0) {
    badge.textContent = chatUnreadCount > 99 ? '99+' : chatUnreadCount;
    badge.classList.add('show');
  } else {
    badge.classList.remove('show');
  }
}

function escapeHtml(str) {
  var div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

//  USDT/KRW 환율 (글로벌 거래소 원화 환산용)
var usdtKrwRate = 1450;  // 기본값 1450원

//  통화 표시 모드
// - 'ORIGINAL': 거래소 기본 통화 (KRW 마켓은 원화, USDT 마켓은 달러)
// - 'KRW': 모든 가격을 원화로 환산
// - 'USDT': 모든 가격을 달러로 환산
var currentCurrencyMode = 'ORIGINAL';

// 현재 선택된 심볼/거래소 (명세서 2-3)
var currentSymbol = null;
var currentExchangeId = null;

// TradingView 위젯 참조
var tvWidget = null;
var mobileTvWidget = null; // 모바일 TradingView 위젯 인스턴스

// 테이블 클릭 안정성을 위한 플래그 (명세서 3-3)
var isTableMouseDown = false;
var tickerRenderPending = false;

//  데이터 수신과 렌더링 분리를 위한 변수
var dirtySet = {};  // { 'UPBIT_SPOT:BTC': true } - 업데이트가 필요한 코인 목록
var flashLastTime = {};  // { 'UPBIT_SPOT:BTC': timestamp } - 마지막 깜빡임 시간
var FLASH_THROTTLE_MS = 500;  // 깜빡임 최소 간격 500ms

// ---
//  뷰포트 기반 차등 구독 시스템 변수
// ---
var subscribeDebounceTimer = null;  // Debounce 타이머
var SUBSCRIBE_DEBOUNCE_MS = 300;    // 300ms 디바운스
var lastSubscribedSymbols = '';     // 마지막 구독 심볼 (변경 감지용)
var renderLoopRunning = false;  // 렌더링 루프 실행 중 여부

//  가상 스크롤(Virtual Scrolling) 변수
//  Compact Mode: CSS와 동기화 (45px → 35px)
var ROW_HEIGHT = 35;        // 행 높이 (고정)
var VISIBLE_BUFFER = 10;    // 위아래 버퍼 행 수
var allFilteredCoins = [];  // 필터링/정렬된 전체 코인 배열
var virtualScrollState = {
  startIndex: 0,
  endIndex: 30,
  lastScrollTop: 0
};
var isVirtualScrollEnabled = true;  // 가상 스크롤 활성화 여부

//  Page Visibility API를 위한 변수
var isPageVisible = true;  // 탭이 보이는 상태인지 여부

//  ResizeObserver 기반 차트 렌더링 (setTimeout 대체)
var desktopChartObserver = null;  // 데스크톱 차트 컨테이너 ResizeObserver
var mobileChartObserver = null;   // 모바일 차트 컨테이너 ResizeObserver
var pendingDesktopSymbol = null;  // 위젯 생성 대기 중인 데스크톱 심볼
var pendingMobileSymbol = null;   // 위젯 생성 대기 중인 모바일 심볼
var tvScriptLoaded = false;       // tv.js 로드 완료 여부

//  Intl.NumberFormat 캐싱 (GC 방지, 10배 이상 성능 향상)
// - 매번 toLocaleString 호출 시 내부적으로 새 포맷터 생성 → 매우 느림
// - 미리 생성해두고 .format() 메서드만 호출 → 10배+ 빠름
var priceFormatter0 = new Intl.NumberFormat('ko-KR', { 
  minimumFractionDigits: 0, 
  maximumFractionDigits: 0 
});
var priceFormatter2 = new Intl.NumberFormat('ko-KR', { 
  minimumFractionDigits: 0, 
  maximumFractionDigits: 2 
});
var priceFormatter4 = new Intl.NumberFormat('ko-KR', { 
  minimumFractionDigits: 0, 
  maximumFractionDigits: 4 
});
var priceFormatter8 = new Intl.NumberFormat('ko-KR', { 
  minimumFractionDigits: 0, 
  maximumFractionDigits: 8 
});

//  Time-Slicing 예산 (ms)
var RENDER_BUDGET_MS = 8;  // 한 프레임당 최대 8ms만 렌더링에 사용

// 프론트 기준 모멘텀 지원 분봉 (서버 ALLOWED_TIMEFRAMES와 동일)
var SUPPORTED_MOMENTUM_UNITS = [1, 3, 5, 10, 15, 30, 60, 240];

function isSupportedMomentumUnit(unit) {
  return SUPPORTED_MOMENTUM_UNITS.indexOf(unit) !== -1;
}

// ---
// 법적 고지 모달 (프론트 개선 3)
// ---
var legalContents = {
  ko: {
    terms: {
      title: '이용약관',
      body: '<h4>제1조 (목적)</h4>' +
        '<p>본 약관은 To The Moon List(이하 "서비스")가 제공하는 암호화폐 모멘텀 정보 서비스의 이용조건 및 절차에 관한 기본적인 사항을 규정함을 목적으로 합니다.</p>' +
        '<h4>제2조 (서비스의 제공)</h4>' +
        '<p>1. 서비스는 다음과 같은 정보를 제공합니다:</p>' +
        '<ul>' +
        '<li>암호화폐 실시간 시세 정보</li>' +
        '<li>기술적 분석 기반 상승/하락 확률 정보</li>' +
        '<li>거래소 연동 차트 (TradingView 제공)</li>' +
        '<li>익명 채팅 서비스</li>' +
        '</ul>' +
        '<p>2. 서비스는 365일 24시간 제공을 위해 노력하나, 이를 보증하지는 않습니다. 서버 점검, 통신 장애, 거래소 API 오류 등으로 서비스가 일시 중단될 수 있습니다.</p>' +
        '<h4>제3조 (이용자의 의무)</h4>' +
        '<p>1. 이용자는 서비스를 통해 얻은 정보를 참고용으로만 사용해야 합니다.</p>' +
        '<p>2. 익명 채팅 서비스 이용 시 타인을 비방하거나, 욕설, 광고, 불법 정보를 게시해서는 안 됩니다.</p>' +
        '<p>3. 서비스 운영을 방해하는 행위(과도한 트래픽 유발, 자동화된 접근 등)를 해서는 안 됩니다.</p>' +
        '<h4>제4조 (면책조항)</h4>' +
        '<p>1. 본 서비스에서 제공하는 모든 정보는 투자판단을 위한 참고용 일반 정보이며, 어떠한 경우에도 특정 금융투자상품 또는 암호화폐의 매수·매도·보유에 대한 투자자문이나 투자권유로 해석될 수 없습니다.</p>' +
        '<p>2. 투자 결정에 따른 모든 책임은 이용자 본인에게 있습니다.</p>' +
        '<p>3. 실시간 데이터는 거래소 API를 통해 제공되며, 네트워크 지연 또는 거래소 서버 상황에 따라 실제 가격과 차이가 있을 수 있습니다.</p>' +
        '<p>4. 서비스 운영자는 이용자의 투자 손익에 대해 어떠한 책임도 지지 않습니다.</p>' +
        '<h4>제5조 (저작권)</h4>' +
        '<p>1. 본 서비스의 콘텐츠(UI 디자인, 코드, 로고 등)에 대한 저작권은 To The Moon List에 있습니다.</p>' +
        '<p>2. 차트 솔루션은 TradingView에서 제공합니다.</p>' +
        '<h4>제6조 (약관의 변경)</h4>' +
        '<p>서비스 운영자는 필요한 경우 약관을 변경할 수 있으며, 변경된 약관은 서비스 화면에 공지함으로써 효력을 발생합니다.</p>' +
        '<p style="margin-top: 20px; color: #888;">본 약관은 2025년 11월 30일부터 시행됩니다.</p>'
    },
    privacy: {
      title: '개인정보처리방침',
      body: '<p>To The Moon List(이하 "서비스")는 이용자의 개인정보 보호를 중요하게 생각하며, 다음과 같은 방침을 두고 있습니다.</p>' +
        '<h4>1. 수집하는 개인정보</h4>' +
        '<p>본 서비스는 별도의 회원가입 없이 이용 가능하며, 개인정보를 직접 수집하지 않습니다.</p>' +
        '<h4>2. 자동 수집 정보</h4>' +
        '<p>서비스 개선 및 통계 분석을 위해 다음 정보가 자동으로 수집될 수 있습니다:</p>' +
        '<ul>' +
        '<li>IP 주소</li>' +
        '<li>브라우저 종류 및 버전</li>' +
        '<li>접속 시간, 방문 페이지</li>' +
        '<li>운영체제 정보</li>' +
        '</ul>' +
        '<h4>3. 쿠키 사용</h4>' +
        '<p>본 서비스는 사용자 경험 개선을 위해 쿠키를 사용합니다:</p>' +
        '<ul>' +
        '<li>언어 설정 저장</li>' +
        '<li>채팅 닉네임 저장</li>' +
        '<li>UI 설정 저장</li>' +
        '</ul>' +
        '<p>이용자는 브라우저 설정에서 쿠키 사용을 거부할 수 있습니다.</p>' +
        '<h4>4. 광고 및 제3자 서비스</h4>' +
        '<p>본 서비스는 다음과 같은 제3자 서비스를 사용할 수 있으며, 해당 서비스의 개인정보처리방침이 적용됩니다:</p>' +
        '<ul>' +
        '<li>Google Analytics (방문 통계)</li>' +
        '<li>Google AdSense (광고 서비스)</li>' +
        '<li>TradingView (차트 서비스)</li>' +
        '</ul>' +
        '<h4>5. 개인정보의 보관 및 파기</h4>' +
        '<p>자동 수집된 정보는 서비스 분석 목적으로만 사용되며, 관련 법령에 따라 보관 후 파기됩니다.</p>' +
        '<h4>6. 문의</h4>' +
        '<p>개인정보 관련 문의사항은 서비스 내 채팅을 통해 To The Moon List 관리자에게 문의하실 수 있습니다.</p>' +
        '<p style="margin-top: 20px; color: #888;">본 개인정보처리방침은 2025년 11월 30일부터 시행됩니다.</p>'
    },
    disclaimer: {
      title: '투자 유의사항',
      body: '<h4>[WARN] 중요 안내</h4>' +
        '<p style="color: #f44336; font-weight: bold;">암호화폐 투자는 원금 손실의 위험이 있습니다.</p>' +
        '<h4>1. 정보의 성격</h4>' +
        '<p>본 서비스에서 제공하는 상승/하락 확률은 과거 캔들 데이터의 고가·저가 돌파 패턴을 분석한 통계적 지표입니다. 이는 미래 가격을 예측하거나 보장하지 않습니다.</p>' +
        '<h4>2. 투자 권유 및 자문 아님</h4>' +
        '<p>본 서비스의 콘텐츠는 투자 판단을 위한 참고 자료일 뿐, 특정 암호화폐·투자 상품·전략에 대한 매수, 매도, 보유를 권유하거나 이에 대해 자문하는 것이 아닙니다. 이 사이트에는 광고 또는 제휴 링크가 포함될 수 있으나, 이러한 요소는 제공되는 정보의 성격을 변경하지 않으며, 어떠한 경우에도 투자자문 또는 투자권유로 해석될 수 없습니다.</p>' +
        '<h4>3. 데이터 정확성</h4>' +
        '<p>실시간 데이터는 거래소 API를 통해 제공되며, 네트워크 지연 또는 거래소 서버 상황에 따라 실제 가격과 차이가 있을 수 있습니다.</p>' +
        '<h4>4. 책임의 한계</h4>' +
        '<p>본 서비스를 참고한 투자 결정으로 인한 손익에 대해 서비스 운영자는 어떠한 책임도 지지 않습니다.</p>' +
        '<h4>5. 투자 원칙</h4>' +
        '<ul>' +
        '<li>감당할 수 있는 금액만 투자하세요.</li>' +
        '<li>분산 투자를 권장합니다.</li>' +
        '<li>충분한 조사 후 투자 결정을 내리세요.</li>' +
        '<li>손절매 기준을 미리 설정하세요.</li>' +
        '<li>레버리지 거래는 위험이 더 큽니다.</li>' +
        '</ul>' +
        '<p style="margin-top: 20px; color: #888;">본 유의사항은 2025년 11월 30일부터 시행됩니다.</p>'
    }
  },
  en: {
    terms: {
      title: 'Terms of Service',
      body: '<h4>Article 1 (Purpose)</h4>' +
        '<p>These terms govern the conditions and procedures for using the cryptocurrency momentum information service provided by To The Moon List (the "Service").</p>' +
        '<h4>Article 2 (Service Provision)</h4>' +
        '<p>1. The Service provides the following information:</p>' +
        '<ul>' +
        '<li>Real-time cryptocurrency price information</li>' +
        '<li>Technical analysis-based up/down probability information</li>' +
        '<li>Exchange-linked charts (powered by TradingView)</li>' +
        '<li>Anonymous chat service</li>' +
        '</ul>' +
        '<p>2. The Service strives to operate 24/7, but this is not guaranteed. The Service may be temporarily suspended due to server maintenance, network issues, or exchange API errors.</p>' +
        '<h4>Article 3 (User Obligations)</h4>' +
        '<p>1. Users must use information obtained through the Service for reference purposes only.</p>' +
        '<p>2. When using the anonymous chat service, users must not defame others, use profanity, post advertisements, or share illegal information.</p>' +
        '<p>3. Users must not engage in activities that disrupt Service operations (excessive traffic generation, automated access, etc.).</p>' +
        '<h4>Article 4 (Disclaimer)</h4>' +
        '<p>1. All information provided by this Service is general information for investment reference purposes only and shall not, under any circumstances, be interpreted as investment advice or a solicitation to buy, sell, or hold any specific financial investment product or cryptocurrency.</p>' +
        '<p>2. All responsibility for investment decisions lies with the user.</p>' +
        '<p>3. Real-time data is provided through exchange APIs and may differ from actual prices due to network delays or exchange server conditions.</p>' +
        '<p>4. The Service operator assumes no responsibility for users&#39; investment gains or losses.</p>' +
        '<h4>Article 5 (Copyright)</h4>' +
        '<p>1. Copyright of the Service content (UI design, code, logo, etc.) belongs to To The Moon List.</p>' +
        '<p>2. Chart solutions are provided by TradingView.</p>' +
        '<h4>Article 6 (Amendment of Terms)</h4>' +
        '<p>The Service operator may amend these terms as necessary, and amended terms take effect upon notification on the Service.</p>' +
        '<p style="margin-top: 20px; color: #888;">These terms take effect from November 30, 2025.</p>'
    },
    privacy: {
      title: 'Privacy Policy',
      body: '<p>To The Moon List (the "Service") values the protection of user privacy and maintains the following policy.</p>' +
        '<h4>1. Personal Information Collected</h4>' +
        '<p>This Service can be used without registration and does not directly collect personal information.</p>' +
        '<h4>2. Automatically Collected Information</h4>' +
        '<p>The following information may be automatically collected for service improvement and statistical analysis:</p>' +
        '<ul>' +
        '<li>IP address</li>' +
        '<li>Browser type and version</li>' +
        '<li>Access time, pages visited</li>' +
        '<li>Operating system information</li>' +
        '</ul>' +
        '<h4>3. Cookie Usage</h4>' +
        '<p>This Service uses cookies to improve user experience:</p>' +
        '<ul>' +
        '<li>Language preference storage</li>' +
        '<li>Chat nickname storage</li>' +
        '<li>UI settings storage</li>' +
        '</ul>' +
        '<p>Users can refuse cookie usage in their browser settings.</p>' +
        '<h4>4. Advertising and Third-Party Services</h4>' +
        '<p>This Service may use the following third-party services, and their respective privacy policies apply:</p>' +
        '<ul>' +
        '<li>Google Analytics (visitor statistics)</li>' +
        '<li>Google AdSense (advertising service)</li>' +
        '<li>TradingView (chart service)</li>' +
        '</ul>' +
        '<h4>5. Retention and Disposal of Personal Information</h4>' +
        '<p>Automatically collected information is used only for service analysis purposes and is disposed of in accordance with relevant laws.</p>' +
        '<h4>6. Inquiries</h4>' +
        '<p>For privacy-related inquiries, please contact the To The Moon List Administrator through the in-service chat.</p>' +
        '<p style="margin-top: 20px; color: #888;">This Privacy Policy takes effect from November 30, 2025.</p>'
    },
    disclaimer: {
      title: 'Investment Disclaimer',
      body: '<h4>[WARN] Important Notice</h4>' +
        '<p style="color: #f44336; font-weight: bold;">Cryptocurrency investment carries the risk of losing your principal.</p>' +
        '<h4>1. Nature of Information</h4>' +
        '<p>The up/down probabilities provided by this Service are statistical indicators analyzing high/low breakout patterns from historical candle data. These do not predict or guarantee future prices.</p>' +
        '<h4>2. No Investment Advice or Solicitation</h4>' +
        '<p>The content provided by this Service is for informational and reference purposes only. It does not recommend or advise on the purchase, sale, or holding of any specific cryptocurrency, investment product, or strategy. This site may include advertisements or affiliate links, but such elements do not change the informational nature of the content and shall not, under any circumstances, be interpreted as investment advice or a solicitation to invest.</p>' +
        '<h4>3. Data Accuracy</h4>' +
        '<p>Real-time data is provided through exchange APIs and may differ from actual prices due to network delays or exchange server conditions.</p>' +
        '<h4>4. Limitation of Liability</h4>' +
        '<p>The Service operator assumes no responsibility for any gains or losses resulting from investment decisions made based on this Service.</p>' +
        '<h4>5. Investment Principles</h4>' +
        '<ul>' +
        '<li>Only invest what you can afford to lose.</li>' +
        '<li>Diversification is recommended.</li>' +
        '<li>Make investment decisions after sufficient research.</li>' +
        '<li>Set stop-loss levels in advance.</li>' +
        '<li>Leveraged trading carries greater risk.</li>' +
        '</ul>' +
        '<p style="margin-top: 20px; color: #888;">This disclaimer takes effect from November 30, 2025.</p>'
    }
  }
};

function openLegalModal(type) {
  var langContents = legalContents[currentLang] || legalContents['ko'];
  var content = langContents[type];
  if (!content) return;
  
  document.getElementById('legalModalTitle').textContent = content.title;
  document.getElementById('legalModalBody').innerHTML = content.body;
  document.getElementById('legalModalOverlay').classList.add('active');
  
  // 모달 열릴 때 body 스크롤 방지 (이미 hidden이지만 명시적으로)
  document.body.style.overflow = 'hidden';
}

function closeLegalModal() {
  document.getElementById('legalModalOverlay').classList.remove('active');
}

// 모달 배경 클릭으로 닫기
document.addEventListener('click', function(e) {
  if (e.target.id === 'legalModalOverlay') {
    closeLegalModal();
  }
});

// ESC 키로 모달 닫기
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    var legalModal = document.getElementById('legalModalOverlay');
    if (legalModal && legalModal.classList.contains('active')) {
      closeLegalModal();
    }
  }
});

// ---
// 거래소 표시 라벨 맵 (명세서 4-2)
//  거래소명 축약 (4글자 이내, 줄바꿈 방지)
//  다국어 지원
// ---
function getExchangeDisplayName(exchangeId) {
  var names = {
    ko: {
      'UPBIT_SPOT': '업비트',
      'BITHUMB_SPOT': '빗썸',
      'BINANCE_SPOT': '바이낸스',
      'BINANCE_FUTURES': '바낸선물',
      'OKX_SPOT': 'OKX',
      'OKX_FUTURES': 'OKX선물',
      'BYBIT_SPOT': '바이빗',
      'BYBIT_FUTURES': '바빗선물'
    },
    en: {
      'UPBIT_SPOT': 'Upbit',
      'BITHUMB_SPOT': 'Bithumb',
      'BINANCE_SPOT': 'Binance',
      'BINANCE_FUTURES': 'Binance F',
      'OKX_SPOT': 'OKX',
      'OKX_FUTURES': 'OKX F',
      'BYBIT_SPOT': 'Bybit',
      'BYBIT_FUTURES': 'Bybit F'
    }
  };
  var langNames = names[currentLang] || names['ko'];
  return langNames[exchangeId] || exchangeId;
}

// 기존 호환성을 위해 exchangeDisplayNames 유지 (한국어 기본값)
var exchangeDisplayNames = {
  'UPBIT_SPOT': '업비트',
  'BITHUMB_SPOT': '빗썸',
  'BINANCE_SPOT': '바이낸스',
  'BINANCE_FUTURES': '바낸선물',
  'OKX_SPOT': 'OKX',
  'OKX_FUTURES': 'OKX선물',
  'BYBIT_SPOT': '바이빗',
  'BYBIT_FUTURES': '바빗선물'
};

// ---
// TradingView 심볼 매핑 (명세서 1-2)
// ---
var tvSymbolMap = {
  // 업비트 현물
  'UPBIT_SPOT:BTC': 'UPBIT:BTCKRW',
  'UPBIT_SPOT:ETH': 'UPBIT:ETHKRW',
  'UPBIT_SPOT:XRP': 'UPBIT:XRPKRW',
  'UPBIT_SPOT:SOL': 'UPBIT:SOLKRW',
  'UPBIT_SPOT:ADA': 'UPBIT:ADAKRW',
  'UPBIT_SPOT:DOT': 'UPBIT:DOTKRW',
  'UPBIT_SPOT:LINK': 'UPBIT:LINKKRW',
  'UPBIT_SPOT:AVAX': 'UPBIT:AVAXKRW',
  'UPBIT_SPOT:DOGE': 'UPBIT:DOGEKRW',
  'UPBIT_SPOT:MATIC': 'UPBIT:MATICKRW',
  
  // 빗썸 현물
  'BITHUMB_SPOT:BTC': 'BITHUMB:BTCKRW',
  'BITHUMB_SPOT:ETH': 'BITHUMB:ETHKRW',
  'BITHUMB_SPOT:XRP': 'BITHUMB:XRPKRW',
  'BITHUMB_SPOT:SOL': 'BITHUMB:SOLKRW',
  'BITHUMB_SPOT:ADA': 'BITHUMB:ADAKRW',
  'BITHUMB_SPOT:DOT': 'BITHUMB:DOTKRW',
  'BITHUMB_SPOT:LINK': 'BITHUMB:LINKKRW',
  'BITHUMB_SPOT:AVAX': 'BITHUMB:AVAXKRW',
  'BITHUMB_SPOT:DOGE': 'BITHUMB:DOGEKRW',
  'BITHUMB_SPOT:MATIC': 'BITHUMB:MATICKRW'
  
  // 바이낸스/바이비트 확장용 (실제 심볼은 연동 시 수정)
  // 'BINANCE_SPOT:BTC':    'BINANCE:BTCUSDT',
  // 'BINANCE_FUTURES:BTC': 'BINANCE:BTCUSDT.P',
  // 'BYBIT_SPOT:BTC':      'BYBIT:BTCUSDT',
  // 'BYBIT_FUTURES:BTC':   'BYBIT:BTCUSDT.P'
};

// ---
// 거래소별 거래 URL 템플릿 (명세서 4-2)
//  심볼이 이제 짧은 형태(BTC)로 저장되므로 replace 불필요
// ---
var tradeUrls = {
  UPBIT_SPOT: function(symbol) {
    return 'https://upbit.com/exchange?code=CRIX.UPBIT.KRW-' + symbol;
  },
  BITHUMB_SPOT: function(symbol) {
    return 'https://www.bithumb.com/react/trade/order/' + symbol + '-KRW';
  },
  //  바이낸스 URL - 심볼이 이미 BTC 형태
  BINANCE_SPOT: function(symbol) {
    return 'https://www.binance.com/ko/trade/' + symbol + '_USDT';
  },
  BINANCE_FUTURES: function(symbol) {
    return 'https://www.binance.com/ko/futures/' + symbol + 'USDT';
  },
  //  OKX URL - 심볼이 이미 BTC 형태
  OKX_SPOT: function(symbol) {
    return 'https://www.okx.com/trade-spot/' + symbol.toLowerCase() + '-usdt';
  },
  OKX_FUTURES: function(symbol) {
    return 'https://www.okx.com/trade-swap/' + symbol.toLowerCase() + '-usdt-swap';
  },
  BYBIT_SPOT: function(symbol) {
    return 'https://www.bybit.com/trade/spot/' + symbol + '/USDT';
  },
  BYBIT_FUTURES: function(symbol) {
    return 'https://www.bybit.com/trade/usdt/' + symbol + 'USDT';
  }
};

// ---
// 거래 버튼 라벨 (server73: CSS 도트로 업그레이드)
// ---
//  거래소 버튼 라벨 (다국어 지원)
function getExchangeLabel(exchangeId) {
  var labels = {
    ko: {
      'UPBIT_SPOT': '<span class="dot upbit"></span>업비트',
      'BITHUMB_SPOT': '<span class="dot bithumb"></span>빗썸',
      'BINANCE_SPOT': '<span class="dot binance"></span>바이낸스',
      'BINANCE_FUTURES': '<span class="dot binance futures"></span>바낸선물',
      'OKX_SPOT': '<span class="dot okx"></span>OKX',
      'OKX_FUTURES': '<span class="dot okx futures"></span>OKX선물',
      'BYBIT_SPOT': '<span class="dot bybit"></span>바이비트',
      'BYBIT_FUTURES': '<span class="dot bybit futures"></span>바빗선물'
    },
    en: {
      'UPBIT_SPOT': '<span class="dot upbit"></span>Upbit',
      'BITHUMB_SPOT': '<span class="dot bithumb"></span>Bithumb',
      'BINANCE_SPOT': '<span class="dot binance"></span>Binance',
      'BINANCE_FUTURES': '<span class="dot binance futures"></span>Binance F',
      'OKX_SPOT': '<span class="dot okx"></span>OKX',
      'OKX_FUTURES': '<span class="dot okx futures"></span>OKX Futures',
      'BYBIT_SPOT': '<span class="dot bybit"></span>Bybit',
      'BYBIT_FUTURES': '<span class="dot bybit futures"></span>Bybit F'
    }
  };
  var langLabels = labels[currentLang] || labels['ko'];
  return langLabels[exchangeId] || exchangeId;
}

//  코인 상세 패널용 거래소 라벨 (이모지 포함)
function getExchangeLabelWithEmoji(exchangeId) {
  var labels = {
    ko: {
      'UPBIT_SPOT': '<span class="dot upbit"></span> 업비트',
      'BITHUMB_SPOT': '<span class="dot bithumb"></span> 빗썸',
      'BINANCE_SPOT': '<span class="dot binance"></span> 바이낸스',
      'BINANCE_FUTURES': '<span class="dot binance futures"></span> 바낸선물',
      'OKX_SPOT': '<span class="dot okx"></span> OKX',
      'OKX_FUTURES': '<span class="dot okx futures"></span> OKX선물',
      'BYBIT_SPOT': '<span class="dot bybit"></span> 바이비트',
      'BYBIT_FUTURES': '<span class="dot bybit futures"></span> 바빗선물'
    },
    en: {
      'UPBIT_SPOT': '<span class="dot upbit"></span> Upbit',
      'BITHUMB_SPOT': '<span class="dot bithumb"></span> Bithumb',
      'BINANCE_SPOT': '<span class="dot binance"></span> Binance',
      'BINANCE_FUTURES': '<span class="dot binance futures"></span> Binance F',
      'OKX_SPOT': '<span class="dot okx"></span> OKX',
      'OKX_FUTURES': '<span class="dot okx futures"></span> OKX Futures',
      'BYBIT_SPOT': '<span class="dot bybit"></span> Bybit',
      'BYBIT_FUTURES': '<span class="dot bybit futures"></span> Bybit F'
    }
  };
  var langLabels = labels[currentLang] || labels['ko'];
  return langLabels[exchangeId] || exchangeId;
}

//  현재 활성화된 거래소 (글로벌 거래소 포함)
var activeExchangesList = ['UPBIT_SPOT', 'BITHUMB_SPOT', 'BINANCE_SPOT', 'BINANCE_FUTURES', 'OKX_SPOT', 'OKX_FUTURES'];

// 모바일 브레이크포인트
var MOBILE_BREAKPOINT = 768;

// ---
// 모바일 감지 함수 (명세서 5-1)
// ---
function isMobile() {
  return window.innerWidth <= MOBILE_BREAKPOINT;
}

// ---
// 모멘텀 분봉 → TradingView interval 변환 (명세서 4-1)
// ---
function getTvIntervalFromMomentum() {
  // TradingView는 '1', '3', '5', '15', '60', '240' 등의 문자열을 interval로 사용
  var n = parseInt(currentMomentumTimeframe, 10);
  if (!n || n <= 0) n = 5;
  return String(n);
}

// ---
// 유틸리티 함수
// ---
/*  formatPrice - 캐싱된 Intl.NumberFormat 사용 (10배+ 성능 향상) */
function formatPrice(price) {
  // 모든 가격을 천 단위 콤마 포함 전체 숫자로 표시 (축약 없음)
  // toLocaleString 대신 미리 생성된 포맷터의 .format() 메서드 사용
  if (price >= 1000) {
    // 1000원 이상: 정수로 표시 (콤마 포함)
    return priceFormatter0.format(Math.round(price));
  } else if (price >= 1) {
    // 1원 이상 1000원 미만: 소수점 2자리까지
    return priceFormatter2.format(price);
  } else if (price >= 0.01) {
    // 0.01 이상: 소수점 4자리까지
    return priceFormatter4.format(price);
  } else {
    // 아주 작은 가격: 소수점 8자리까지
    return priceFormatter8.format(price);
  }
}

//  환산 가격 계산
// - ORIGINAL 모드: 변환 없음
// - KRW 모드: 해외 코인은 price * usdtKrwRate
// - USDT 모드: 국내 코인은 price / usdtKrwRate
function getConvertedPrice(price, exchange) {
  if (currentCurrencyMode === 'ORIGINAL') {
    return { price: price, isConverted: false };
  }
  
  var isGlobal = isGlobalExchange(exchange);
  
  if (currentCurrencyMode === 'KRW') {
    // 원화 모드: 해외 거래소만 환산
    if (isGlobal) {
      return { price: price * usdtKrwRate, isConverted: true };
    }
    return { price: price, isConverted: false };
  } else if (currentCurrencyMode === 'USDT') {
    // 달러 모드: 국내 거래소만 환산
    if (!isGlobal) {
      return { price: price / usdtKrwRate, isConverted: true };
    }
    return { price: price, isConverted: false };
  }
  
  return { price: price, isConverted: false };
}

//  해외 거래소용 가격 포맷 (통화 모드 반영)
function formatPriceWithCurrency(price, exchange) {
  var converted = getConvertedPrice(price, exchange);
  var displayPrice = converted.price;
  var isConverted = converted.isConverted;
  
  // USDT 모드에서는 소수점 4자리까지 표시
  var formattedPrice;
  if (currentCurrencyMode === 'USDT') {
    if (displayPrice >= 1000) {
      formattedPrice = priceFormatter2.format(displayPrice);
    } else if (displayPrice >= 1) {
      formattedPrice = priceFormatter4.format(displayPrice);
    } else {
      formattedPrice = priceFormatter8.format(displayPrice);
    }
  } else {
    formattedPrice = formatPrice(displayPrice);
  }
  
  // 환산된 가격은 ≈ 표시 추가
  var prefix = isConverted ? '<span class="converted-price">≈ </span>' : '';
  
  // 통화 표시 결정
  if (currentCurrencyMode === 'ORIGINAL') {
    if (isGlobalExchange(exchange)) {
      return prefix + formattedPrice + ' <span class="currency-usdt">₮</span>';
    }
    return prefix + formattedPrice;
  } else if (currentCurrencyMode === 'KRW') {
    // 모두 원화로 통일
    return prefix + formattedPrice;
  } else if (currentCurrencyMode === 'USDT') {
    // 모두 달러로 통일
    return prefix + formattedPrice + ' <span class="currency-usdt">₮</span>';
  }
  
  return prefix + formattedPrice;
}

function formatChange(change) {
  var sign = change >= 0 ? '+' : '';
  return sign + change.toFixed(2) + '%';
}

//  null 처리 추가
//  'CALC' 문자열도 처리
//  type 인자 추가 ('up' | 'down') - 방향별 색상 구분
function getProbClass(prob, type) {
  if (prob === undefined || prob === 'CALC') return 'prob-calc';
  if (prob === null) return 'prob-null';
  if (prob >= 60) {
    // 60% 이상: 상승은 초록색, 하락은 빨간색
    return type === 'down' ? 'prob-high-down' : 'prob-high-up';
  }
  if (prob >= 40) return 'prob-medium';
  return 'prob-low';
}

// ---
// 다중 거래소 필터 함수 (명세서 1-4)
// ---
function getActiveExchangeIds() {
  var labels = document.querySelectorAll('#exchangeFilterGroup [data-exchange-filter]');
  var active = [];
  
  labels.forEach(function(label) {
    var checkbox = label.querySelector('input[type="checkbox"]');
    var id = label.dataset.exchangeFilter;
    if (!id || !checkbox) return;
    
    if (checkbox.checked) {
      active.push(id);
      label.classList.add('active');
    } else {
      label.classList.remove('active');
    }
  });
  
  return active;
}

// ---
// 필터링 및 정렬 (명세서 1-4 renderTable 로직)
//  고도화된 정렬 시스템 - 드롭다운 + 컬럼 헤더 클릭 하이브리드
// ---

//  컬럼 헤더 정렬 상태 관리
var columnSortState = {
  key: null,      // 현재 정렬 중인 컬럼 키 ('exchange', 'symbol', 'price', 'change', 'up', 'down')
  direction: null // 'asc' 또는 'desc'
};

//  해외 거래소인지 확인하는 헬퍼 함수
function isGlobalExchange(exchange) {
  return exchange === 'BINANCE_SPOT' || exchange === 'BINANCE_FUTURES' ||
         exchange === 'OKX_SPOT' || exchange === 'OKX_FUTURES';
}

//  정렬용 가격 계산 (환산가 기준)
// - ORIGINAL 모드: 원화 환산가 기준 (혼합 정렬)
// - KRW 모드: 원화 환산가 기준
// - USDT 모드: 달러 환산가 기준
function getPriceForSorting(coin) {
  var converted = getConvertedPrice(coin.price, coin.exchange);
  return converted.price;
}

//  원화 환산가 계산 (기존 호환용)
// - 국내 거래소: 원화 가격 그대로
// - 해외 거래소: USD 가격 * 환율
function getPriceInKRW(coin) {
  if (isGlobalExchange(coin.exchange)) {
    return coin.price * usdtKrwRate;
  }
  return coin.price;
}

// ---
//  누락된 필터링 헬퍼 함수 추가
// - WebSocket 'R' 메시지 처리 시 allFilteredCoins 갱신에 필요
// - getActiveExchangeIds()를 사용하여 활성 거래소만 필터링
// ---
// ---
//  filterCoins - 서버 순서 유지 버전
// - 거래소 필터 + 검색어 필터만 적용 (정렬 없음)
// - 즐겨찾기 상단 고정은 적용
// - WebSocket R 메시지 처리 시 사용 (isUserSorting = false)
// ---
function filterCoins(sourceCoins) {
  var activeExchanges = getActiveExchangeIds();
  if (activeExchanges.length === 0) {
    lastFavsCount = 0;
    return [];
  }
  
  // 1. 거래소 필터
  var filtered = sourceCoins.filter(function(c) {
    return activeExchanges.indexOf(c.exchange) !== -1;
  });
  
  // 2. 검색어 필터 (Phase 1)
  if (searchKeyword && searchKeyword.length > 0) {
    filtered = filtered.filter(function(c) {
      var symbolUpper = (c.symbol || '').toUpperCase();
      return symbolUpper.indexOf(searchKeyword) !== -1;
    });
  }
  
  // 3. 즐겨찾기 Split (Phase 3) - 정렬은 하지 않음, 순서만 재배치
  var tf = currentMomentumTimeframe;
  var favSet = favoriteCoinsMap[tf] || new Set();
  
  var favs = [];
  var others = [];
  
  filtered.forEach(function(coin) {
    var key = coin.exchange + ':' + coin.symbol;
    if (favSet.has(key)) {
      favs.push(coin);
    } else {
      others.push(coin);
    }
  });
  
  // 4. 구분선용 카운트 업데이트
  lastFavsCount = favs.length;
  
  // 5. Merge (정렬 없이 순서만 변경)
  return favs.concat(others);
}

function getFilteredAndSortedCoins() {
  var activeExchanges = getActiveExchangeIds();
  var sortFilter = document.getElementById('sortFilter').value;
  
  var filtered = coins.slice();
  
  // ---
  // [Phase 1] 거래소 필터 적용
  // ---
  if (activeExchanges.length === 0) {
    // 전체 OFF: 빈 배열 반환 (안내 문구 표시용)
    return [];
  }
  
  filtered = filtered.filter(function(c) {
    return activeExchanges.indexOf(c.exchange) !== -1;
  });
  
  // ---
  // [Phase 2] 검색어 필터링 (server233)
  // - searchKeyword가 있으면 심볼에 포함된 코인만 남김
  // - 대소문자 무시 (searchKeyword는 이미 대문자로 변환됨)
  // ---
  if (searchKeyword && searchKeyword.length > 0) {
    filtered = filtered.filter(function(c) {
      var symbolUpper = (c.symbol || '').toUpperCase();
      return symbolUpper.indexOf(searchKeyword) !== -1;
    });
  }
  
  // ---
  //  null/undefined 값을 맨 아래로 보내는 헬퍼 함수
  // ---
  function handleNullValues(aVal, bVal, isDesc) {
    var aIsNull = (aVal === null || aVal === undefined || aVal === 'CALC');
    var bIsNull = (bVal === null || bVal === undefined || bVal === 'CALC');
    
    if (aIsNull && bIsNull) return 0;
    if (aIsNull) return 1;
    if (bIsNull) return -1;
    return null;
  }
  
  // ---
  //  정렬 비교 함수 (favs/others 공용)
  // ---
  function getSortComparator() {
    if (columnSortState.key !== null) {
      // Case B: 컬럼 헤더로 정렬 중
      return function(a, b) {
        var result = 0;
        var key = columnSortState.key;
        var isDesc = (columnSortState.direction === 'desc');
        
        switch (key) {
          case 'exchange':
            result = a.exchange.localeCompare(b.exchange, 'ko', { numeric: true, sensitivity: 'base' });
            break;
          case 'symbol':
            result = a.symbol.localeCompare(b.symbol, 'ko', { numeric: true, sensitivity: 'base' });
            break;
          case 'price':
            result = getPriceForSorting(a) - getPriceForSorting(b);
            break;
          case 'change':
            result = a.change24h - b.change24h;
            break;
          case 'up':
            var nullResult = handleNullValues(a.upProbability, b.upProbability, isDesc);
            if (nullResult !== null) return nullResult;
            result = a.upProbability - b.upProbability;
            break;
          case 'down':
            var nullResult = handleNullValues(a.downProbability, b.downProbability, isDesc);
            if (nullResult !== null) return nullResult;
            result = a.downProbability - b.downProbability;
            break;
          default:
            result = 0;
        }
        
        return columnSortState.direction === 'desc' ? -result : result;
      };
    } else {
      // Case A: 드롭다운 프리셋으로 정렬
      return function(a, b) {
        var nullResult;
        
        switch (sortFilter) {
          case 'up': 
            nullResult = handleNullValues(a.upProbability, b.upProbability, true);
            if (nullResult !== null) return nullResult;
            return b.upProbability - a.upProbability;
          case 'down': 
            nullResult = handleNullValues(a.downProbability, b.downProbability, true);
            if (nullResult !== null) return nullResult;
            return b.downProbability - a.downProbability;
          case 'change': 
            return b.change24h - a.change24h;
          case 'symbol':
            return a.symbol.localeCompare(b.symbol, 'ko', { numeric: true, sensitivity: 'base' });
          case 'default':
          default: 
            nullResult = handleNullValues(a.upProbability, b.upProbability, true);
            if (nullResult !== null) return nullResult;
            return b.upProbability - a.upProbability;
        }
      };
    }
  }
  
  // ---
  // [Phase 3] Split - 즐겨찾기 / 일반 그룹 분리 (server233)
  // ---
  var tf = currentMomentumTimeframe;
  var favSet = favoriteCoinsMap[tf] || new Set();
  
  var favs = [];
  var others = [];
  
  filtered.forEach(function(coin) {
    var key = coin.exchange + ':' + coin.symbol;
    if (favSet.has(key)) {
      favs.push(coin);
    } else {
      others.push(coin);
    }
  });
  
  // ---
  // [Phase 4] Sort - 각 그룹 개별 정렬 (server233)
  // ---
  var comparator = getSortComparator();
  favs.sort(comparator);
  others.sort(comparator);
  
  // ---
  // [Phase 5] Merge - 즐겨찾기 → 일반 순서로 병합 (server233)
  // ---
  lastFavsCount = favs.length;  // 구분선 표시용
  return favs.concat(others);
}

//  테이블 헤더 정렬 화살표 업데이트
function updateSortArrows() {
  var ths = document.querySelectorAll('thead th[data-sort-key]');
  
  ths.forEach(function(th) {
    var key = th.getAttribute('data-sort-key');
    var baseText = th.textContent.replace(/[▼▲]/g, '').trim();
    
    // 기존 화살표 span 제거
    var existingArrow = th.querySelector('.sort-arrow');
    if (existingArrow) {
      existingArrow.remove();
    }
    
    // sort-active 클래스 제거
    th.classList.remove('sort-active');
    
    // 현재 정렬 중인 컬럼이면 화살표 추가
    if (columnSortState.key === key) {
      th.classList.add('sort-active');
      var arrow = document.createElement('span');
      arrow.className = 'sort-arrow';
      arrow.textContent = columnSortState.direction === 'desc' ? '▼' : '▲';
      th.appendChild(arrow);
    }
  });
}

//  컬럼 헤더 클릭 핸들러
function handleColumnHeaderClick(key) {
  // 같은 컬럼 클릭 시 방향 토글
  if (columnSortState.key === key) {
    columnSortState.direction = columnSortState.direction === 'desc' ? 'asc' : 'desc';
  } else {
    // 새 컬럼 클릭 시 desc(내림차순)로 시작
    columnSortState.key = key;
    columnSortState.direction = 'desc';
  }
  
  //  드롭다운을 "default"로 변경 (커스텀 정렬 중임을 표시)
  document.getElementById('sortFilter').value = 'default';
  
  // 화살표 업데이트
  updateSortArrows();
  
  // 테이블 다시 렌더링
  renderTable();
}

//  드롭다운 변경 핸들러
function handleDropdownChange() {
  //  컬럼 헤더 정렬 상태 초기화
  columnSortState.key = null;
  columnSortState.direction = null;
  
  // 화살표 제거
  updateSortArrows();
  
  // 테이블 다시 렌더링
  renderTable();
}

// ---
// [문제 2 해결] 테이블 렌더링 - DOM Patching 방식 (innerHTML 제거)
//  가상 스크롤(Virtual Scrolling) 적용
// ---
var existingRowIds = new Set(); // 현재 테이블에 있는 행 ID 추적

function renderTable() {
  var tbody = document.getElementById('coinTableBody');
  var wrapper = document.querySelector('.coin-table-wrapper');
  var activeExchanges = getActiveExchangeIds();
  
  // 전체 OFF 상태 안내
  if (activeExchanges.length === 0) {
    tbody.innerHTML = '<tr id="row-message"><td colspan="6" class="no-filter-message">거래소 필터를 선택해 주세요</td></tr>';
    existingRowIds.clear();
    existingRowIds.add('row-message');
    allFilteredCoins = [];
    return;
  }
  
  //  필터링/정렬된 전체 코인 배열 저장
  allFilteredCoins = getFilteredAndSortedCoins();
  
  // ════════════════════════════════════════════════════════════════
  //  filteredCoinIndexMap 구축 (allFilteredCoins 변경 시)
  // ════════════════════════════════════════════════════════════════
  filteredCoinIndexMap = {};
  for (var fi = 0; fi < allFilteredCoins.length; fi++) {
    var fc = allFilteredCoins[fi];
    filteredCoinIndexMap[fc.exchange + ':' + fc.symbol] = fi;
  }
  
  if (allFilteredCoins.length === 0) {
    //  검색 결과 없음 vs 데이터 없음 구분 (i18n 적용)
    var message = t('table.noData');
    if (searchKeyword && searchKeyword.length > 0) {
      message = t('search.noResults');
    }
    tbody.innerHTML = '<tr id="row-message"><td colspan="6" class="no-result-message">' + message + '</td></tr>';
    existingRowIds.clear();
    existingRowIds.add('row-message');
    return;
  }
  
  // 메시지 행이 있으면 제거 (id 또는 .loading 클래스로 찾기)
  var msgRow = document.getElementById('row-message');
  if (msgRow) {
    msgRow.remove();
    existingRowIds.delete('row-message');
  } else {
    //  방어 로직: id가 없어도 .loading 클래스로 찾아서 제거
    var loadingRow = tbody.querySelector('tr td.loading');
    if (loadingRow && loadingRow.parentElement) {
      loadingRow.parentElement.remove();
    }
  }
  
  //  가상 스크롤 렌더링
  renderVirtualRows(wrapper, tbody);
  
  //  렌더링 후 텍스트 잘림 체크 (DOM 업데이트 후 실행)
  setTimeout(checkExchangeColumnOverflow, 100);
}

// ---
//  가상 스크롤 핵심 렌더링 함수
// - 화면에 보이는 행만 렌더링
// - 상단/하단 스페이서로 스크롤바 크기 유지
// ---
function renderVirtualRows(wrapper, tbody) {
  if (!wrapper || !tbody) return;
  if (allFilteredCoins.length === 0) return;
  
  var scrollTop = wrapper.scrollTop || 0;
  var wrapperHeight = wrapper.clientHeight || 600;
  
  // thead 높이 계산 (약 45px)
  var theadHeight = 45;
  
  // 보이는 행 수 계산
  var visibleRowCount = Math.ceil(wrapperHeight / ROW_HEIGHT) + 1;
  
  // 시작/끝 인덱스 계산
  var startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - VISIBLE_BUFFER);
  var endIndex = Math.min(allFilteredCoins.length, startIndex + visibleRowCount + (VISIBLE_BUFFER * 2));
  
  // 상태 저장
  virtualScrollState.startIndex = startIndex;
  virtualScrollState.endIndex = endIndex;
  virtualScrollState.lastScrollTop = scrollTop;
  
  var isMomentumSupported = isSupportedMomentumUnit(parseInt(currentMomentumTimeframe, 10));
  
  // 상단 스페이서 높이
  var topSpacerHeight = startIndex * ROW_HEIGHT;
  // 하단 스페이서 높이
  var bottomSpacerHeight = (allFilteredCoins.length - endIndex) * ROW_HEIGHT;
  
  // 현재 렌더링되어야 하는 행 ID 목록
  var newRowIds = new Set();
  newRowIds.add('virtual-spacer-top');
  newRowIds.add('virtual-spacer-bottom');
  
  // 1. 상단 스페이서 처리
  var topSpacer = document.getElementById('virtual-spacer-top');
  if (!topSpacer) {
    topSpacer = document.createElement('tr');
    topSpacer.id = 'virtual-spacer-top';
    topSpacer.className = 'virtual-spacer';
    var tdTop = document.createElement('td');
    tdTop.colSpan = 6;
    topSpacer.appendChild(tdTop);
    tbody.insertBefore(topSpacer, tbody.firstChild);
  }
  topSpacer.style.height = topSpacerHeight + 'px';
  topSpacer.firstChild.style.height = topSpacerHeight + 'px';
  
  // 2. 보이는 행만 렌더링 (startIndex ~ endIndex)
  for (var i = startIndex; i < endIndex; i++) {
    var coin = allFilteredCoins[i];
    if (!coin) continue;
    
    var rowId = 'row-' + coin.exchange + '-' + coin.symbol;
    newRowIds.add(rowId);
    
    // ---
    //  상승%/하락% 계산 - 이원화 상태 처리
    // - undefined: 로딩 중 ("Calc...", prob-calc)
    // - null: 데이터 부족 ("-", prob-null)
    // - number: 정상 값 (N%, prob-high/medium/low)
    // ---
    var upText = 'Calc...';
    var downText = 'Calc...';
    var upClass = 'prob-calc';
    var downClass = 'prob-calc';
    
    if (isMomentumSupported) {
      //  undefined 또는 'CALC' 문자열 체크: 아직 데이터를 받지 못한 상태
      if (coin.upProbability === undefined || coin.upProbability === 'CALC') {
        upText = 'Calc...';
        upClass = 'prob-calc';
      } else if (coin.upProbability === null) {
        // null: 서버에서 데이터 부족으로 null 반환
        upText = '-';
        upClass = 'prob-null';
      } else {
        // number: 정상 값
        upText = coin.upProbability + '%';
        upClass = getProbClass(coin.upProbability, 'up');
      }
      
      if (coin.downProbability === undefined || coin.downProbability === 'CALC') {
        downText = 'Calc...';
        downClass = 'prob-calc';
      } else if (coin.downProbability === null) {
        downText = '-';
        downClass = 'prob-null';
      } else {
        downText = coin.downProbability + '%';
        downClass = getProbClass(coin.downProbability, 'down');
      }
    } else {
      // 지원하지 않는 타임프레임
      upText = '-';
      downText = '-';
      upClass = 'prob-null';
      downClass = 'prob-null';
    }
    
    var exchangeClass = 'exchange-' + coin.exchange;
    var changeClass = coin.change24h >= 0 ? 'change-positive' : 'change-negative';
    var isSelected = (currentSymbol === coin.symbol && currentExchangeId === coin.exchange);
    var displayName = getExchangeDisplayName(coin.exchange);
    
    var existingRow = document.getElementById(rowId);
    var rowToRender;
    
    if (existingRow) {
      // 행이 있으면: 셀만 업데이트 (DOM Patching)
      updateRowCells(existingRow, coin, displayName, exchangeClass, changeClass, upText, downText, upClass, downClass, isSelected);
      rowToRender = existingRow;
    } else {
      // 행이 없으면: 새로 생성
      rowToRender = createCoinRow(rowId, coin, displayName, exchangeClass, changeClass, upText, downText, upClass, downClass, isSelected);
    }
    
    // ---
    //  즐겨찾기 구분선 처리
    // - 즐겨찾기 그룹의 마지막 행에 .fav-separator 클래스 추가
    // - i === lastFavsCount - 1 일 때가 마지막 즐겨찾기 행
    // ---
    if (lastFavsCount > 0 && i === lastFavsCount - 1) {
      if (!rowToRender.classList.contains('fav-separator')) {
        rowToRender.classList.add('fav-separator');
      }
    } else {
      if (rowToRender.classList.contains('fav-separator')) {
        rowToRender.classList.remove('fav-separator');
      }
    }

    // ---
    //  DOM 순서 강제 동기화
    // - 기존 행이든 새 행이든, 현재 루프 순서(i)에 맞춰 bottomSpacer 바로 위로 이동
    // - 루프가 순차적으로 돌기 때문에 결과적으로 모든 행이 올바르게 정렬됨
    // - 이렇게 해야 데이터 순서와 화면 순서가 100% 일치함
    // ---
    var bottomSpacer = document.getElementById('virtual-spacer-bottom');
    if (bottomSpacer) {
      tbody.insertBefore(rowToRender, bottomSpacer);
    } else {
      tbody.appendChild(rowToRender);
    }
  }
  
  // 3. 하단 스페이서 처리
  var bottomSpacer = document.getElementById('virtual-spacer-bottom');
  if (!bottomSpacer) {
    bottomSpacer = document.createElement('tr');
    bottomSpacer.id = 'virtual-spacer-bottom';
    bottomSpacer.className = 'virtual-spacer';
    var tdBottom = document.createElement('td');
    tdBottom.colSpan = 6;
    bottomSpacer.appendChild(tdBottom);
    tbody.appendChild(bottomSpacer);
  }
  bottomSpacer.style.height = bottomSpacerHeight + 'px';
  bottomSpacer.firstChild.style.height = bottomSpacerHeight + 'px';
  
  // 4. 더 이상 필요 없는 행 제거 (가상 스크롤 범위 밖)
  existingRowIds.forEach(function(rowId) {
    if (!newRowIds.has(rowId)) {
      var oldRow = document.getElementById(rowId);
      if (oldRow) oldRow.remove();
    }
  });
  
  existingRowIds = newRowIds;
  
  // ---
  //  보고 있는 코인 목록을 서버에 구독 요청 (Debounce 적용)
  // - 스크롤 시 매번 전송하지 않고 300ms 디바운스
  // - 데이터 소모량 대폭 절감 (보고 있는 코인만 실시간 수신)
  // ---
  sendVisibleSymbolsSubscription();
}

// ---
//  보고 있는 코인 구독 요청 함수 (Debounce 300ms)
// - 화면에 보이는 코인들의 심볼을 서버에 전송
// - 서버는 이 목록에 있는 코인만 실시간 전송
// ---
function sendVisibleSymbolsSubscription() {
  // Debounce: 이전 타이머 취소
  if (subscribeDebounceTimer) {
    clearTimeout(subscribeDebounceTimer);
  }
  
  subscribeDebounceTimer = setTimeout(function() {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    
    // 현재 보이는 코인들의 심볼 추출
    var visibleSymbols = [];
    var visibleKeys = [];  // exchange:symbol 형태
    
    for (var i = virtualScrollState.startIndex; i < virtualScrollState.endIndex; i++) {
      var coin = allFilteredCoins[i];
      if (coin) {
        visibleSymbols.push(coin.symbol);
        visibleKeys.push(coin.exchange + ':' + coin.symbol);
      }
    }
    
    // 변경 없으면 전송 스킵 (불필요한 메시지 방지)
    var symbolsKey = visibleKeys.join(',');
    if (symbolsKey === lastSubscribedSymbols) {
      return;
    }
    lastSubscribedSymbols = symbolsKey;
    
    // 서버에 구독 요청
    ws.send(JSON.stringify({
      type: 'subscribe',
      visibleSymbols: visibleSymbols,
      visibleKeys: visibleKeys
    }));
    
    // console.log(' 구독 요청:', visibleSymbols.length, '개 심볼');
  }, SUBSCRIBE_DEBOUNCE_MS);
}
// ---
//  테이블 스크롤 이벤트 핸들러
// - 스크롤 위치 기반으로 보이는 행 다시 렌더링
// ---
var scrollRAFPending = false;

function handleTableScroll() {
  if (scrollRAFPending) return;
  scrollRAFPending = true;
  
  requestAnimationFrame(function() {
    scrollRAFPending = false;
    
    //  스크롤 시 재정렬 로직 삭제!
    // - 데이터 갱신은 WebSocket R 메시지에서만 수행
    // - 스크롤 중에 정렬하면 인덱스와 데이터 싱크가 어긋남
    // - 스크롤은 "이미 정렬된 데이터"를 그리기만 할 것
    
    var wrapper = document.querySelector('.coin-table-wrapper');
    var tbody = document.getElementById('coinTableBody');
    
    if (!wrapper || !tbody || allFilteredCoins.length === 0) return;
    
    // 스크롤 변화량 확인 (작은 변화는 무시)
    var scrollTop = wrapper.scrollTop;
    var scrollDelta = Math.abs(scrollTop - virtualScrollState.lastScrollTop);
    
    // 행 높이의 절반 이상 스크롤해야 갱신
    if (scrollDelta < ROW_HEIGHT / 2) return;
    
    // 새로운 시작/끝 인덱스 계산
    var visibleRowCount = Math.ceil(wrapper.clientHeight / ROW_HEIGHT) + 1;
    var newStartIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - VISIBLE_BUFFER);
    var newEndIndex = Math.min(allFilteredCoins.length, newStartIndex + visibleRowCount + (VISIBLE_BUFFER * 2));
    
    // 인덱스 변화 확인 (변화 없으면 렌더링 스킵)
    if (newStartIndex === virtualScrollState.startIndex && newEndIndex === virtualScrollState.endIndex) {
      virtualScrollState.lastScrollTop = scrollTop;
      return;
    }
    
    // 보이는 행 다시 렌더링
    renderVirtualRows(wrapper, tbody);
  });
}

// 개별 셀 업데이트 함수 (DOM Patching 핵심)
function updateRowCells(row, coin, displayName, exchangeClass, changeClass, upText, downText, upClass, downClass, isSelected) {
  //  row.cells는 HTMLCollection으로 즉시 접근 가능 (querySelectorAll보다 훨씬 빠름)
  var cells = row.cells;
  if (cells.length < 6) return;
  
  // 선택 상태 업데이트
  if (isSelected && !row.classList.contains('selected-row')) {
    row.classList.add('selected-row');
  } else if (!isSelected && row.classList.contains('selected-row')) {
    row.classList.remove('selected-row');
  }
  
  // 셀 0: 거래소 (+ 별 아이콘 + dot)
  if (cells[0].className !== exchangeClass) cells[0].className = exchangeClass;
  
  //  별 아이콘 상태 업데이트
  var starIcon = cells[0].querySelector('.star-icon');
  var isFav = isFavorite(coin.exchange, coin.symbol);
  
  if (!starIcon) {
    // 별 아이콘이 없으면 추가
    starIcon = document.createElement('span');
    starIcon.className = 'star-icon' + (isFav ? ' active' : '');
    starIcon.innerHTML = '&#9733;'; // ★
    starIcon.addEventListener('click', function(e) {
      e.stopPropagation();
      toggleFavorite(coin.exchange, coin.symbol);
    });
    cells[0].insertBefore(starIcon, cells[0].firstChild);
  } else {
    // 별 아이콘 상태 업데이트
    if (isFav && !starIcon.classList.contains('active')) {
      starIcon.classList.add('active');
    } else if (!isFav && starIcon.classList.contains('active')) {
      starIcon.classList.remove('active');
    }
  }
  
  //  거래소 식별용 색상 점 추가/업데이트
  var dot = cells[0].querySelector('.dot');
  if (!dot) {
    // dot이 없으면 생성해서 별 아이콘 다음에 삽입
    dot = document.createElement('span');
    var exchangeKey = coin.exchange.split('_')[0].toLowerCase();
    var dotClass = 'dot ' + exchangeKey;
    if (coin.exchange.includes('FUTURES')) {
      dotClass += ' futures';
    }
    dot.className = dotClass;
    // 별 아이콘 다음에 삽입
    if (starIcon && starIcon.nextSibling) {
      cells[0].insertBefore(dot, starIcon.nextSibling);
    } else {
      cells[0].appendChild(dot);
    }
  }
  
  //  거래소명 텍스트 span 업데이트
  var exchangeNameSpan = cells[0].querySelector('.exchange-name');
  if (exchangeNameSpan) {
    if (exchangeNameSpan.textContent !== displayName) {
      exchangeNameSpan.textContent = displayName;
    }
  } else {
    // span이 없으면 추가
    exchangeNameSpan = document.createElement('span');
    exchangeNameSpan.className = 'exchange-name';
    exchangeNameSpan.textContent = displayName;
    cells[0].appendChild(exchangeNameSpan);
  }
  
  // 셀 1: 심볼 (변경 없음)
  // cells[1] - 스킵
  
  // 셀 2: 가격 (자주 변경)
  //  해외 거래소는 USDT 표시 포함
  var priceHtml = formatPriceWithCurrency(coin.price, coin.exchange);
  if (cells[2].innerHTML !== priceHtml) {
    cells[2].innerHTML = priceHtml;
  }
  
  // 셀 3: 24H 등락률 (자주 변경)
  var changeText = formatChange(coin.change24h);
  if (cells[3].textContent !== changeText) {
    cells[3].textContent = changeText;
  }
  if (cells[3].className !== changeClass) {
    cells[3].className = changeClass;
  }
  
  // 셀 4: 상승% (주기적 변경)
  if (cells[4].textContent !== upText) {
    cells[4].textContent = upText;
  }
  if (cells[4].className !== upClass) {
    cells[4].className = upClass;
  }
  
  // 셀 5: 하락% (주기적 변경)
  if (cells[5].textContent !== downText) {
    cells[5].textContent = downText;
  }
  if (cells[5].className !== downClass) {
    cells[5].className = downClass;
  }
}

// 새 행 생성 함수
function createCoinRow(rowId, coin, displayName, exchangeClass, changeClass, upText, downText, upClass, downClass, isSelected) {
  var row = document.createElement('tr');
  row.id = rowId;
  row.className = 'coin-row' + (isSelected ? ' selected-row' : '');
  row.dataset.symbol = coin.symbol;
  row.dataset.exchangeId = coin.exchange;
  
  // 6개 셀 생성
  var td0 = document.createElement('td');
  td0.className = exchangeClass;
  
  //  별 아이콘 추가
  var starSpan = document.createElement('span');
  starSpan.className = 'star-icon' + (isFavorite(coin.exchange, coin.symbol) ? ' active' : '');
  starSpan.innerHTML = '&#9733;'; // ★
  starSpan.addEventListener('click', function(e) {
    e.stopPropagation(); // 행 클릭 이벤트 방지
    toggleFavorite(coin.exchange, coin.symbol);
  });
  td0.appendChild(starSpan);
  
  //  거래소 식별용 색상 점 추가
  var dot = document.createElement('span');
  var exchangeKey = coin.exchange.split('_')[0].toLowerCase(); // BINANCE_FUTURES -> binance
  var dotClass = 'dot ' + exchangeKey;
  if (coin.exchange.includes('FUTURES')) {
    dotClass += ' futures'; // 선물: 사각형 점
  }
  dot.className = dotClass;
  td0.appendChild(dot);
  
  //  텍스트를 span으로 감싸기 (CSS로 숨김/표시 제어)
  var exchangeTextSpan = document.createElement('span');
  exchangeTextSpan.className = 'exchange-name';
  exchangeTextSpan.textContent = displayName;
  td0.appendChild(exchangeTextSpan);
  
  var td1 = document.createElement('td');
  td1.textContent = coin.symbol;
  
  var td2 = document.createElement('td');
  td2.className = 'price';
  //  해외 거래소는 USDT 표시 포함
  td2.innerHTML = formatPriceWithCurrency(coin.price, coin.exchange);
  
  var td3 = document.createElement('td');
  td3.className = changeClass;
  td3.textContent = formatChange(coin.change24h);
  
  var td4 = document.createElement('td');
  td4.className = upClass;
  td4.textContent = upText;
  
  var td5 = document.createElement('td');
  td5.className = downClass;
  td5.textContent = downText;
  
  row.appendChild(td0);
  row.appendChild(td1);
  row.appendChild(td2);
  row.appendChild(td3);
  row.appendChild(td4);
  row.appendChild(td5);
  
  return row;
}

// ---
//  requestAnimationFrame 기반 렌더링 루프
// - dirtySet에 있는 코인들만 처리
// - DOM 조작을 브라우저 주사율에 맞춰 수행
//  Page Visibility 대응 추가
// ---
function startRenderLoop() {
  if (renderLoopRunning) return;
  renderLoopRunning = true;
  
  function renderFrame() {
    //  탭이 숨겨지면 렌더링 루프 즉시 중단 (CPU 절약)
    if (!isPageVisible) {
      renderLoopRunning = false;
      dirtySet = {};  // 대기열 비우기 (탭 복귀 시 renderTable()로 동기화)
      console.log(' 탭 숨김 감지 - 렌더링 루프 중단');
      return;
    }
    
    // dirtySet이 비어있으면 루프 중단
    var keys = Object.keys(dirtySet);
    if (keys.length === 0) {
      renderLoopRunning = false;
      return;
    }
    
    // 사용자가 테이블 위에서 마우스를 누르고 있으면 잠시 대기
    if (isTableMouseDown) {
      requestAnimationFrame(renderFrame);
      return;
    }
    
    //  Time-Slicing: 8ms 예산 내에서만 작업
    var frameStart = performance.now();
    var now = Date.now();
    var processedKeys = [];  // 처리 완료된 키 목록
    
    // for 루프 사용 (forEach와 달리 중간에 break 가능)
    for (var i = 0; i < keys.length; i++) {
      //  예산 초과 체크 - 8ms 지나면 즉시 중단
      if (performance.now() - frameStart > RENDER_BUDGET_MS) {
        console.log(' Time-Slicing: ' + processedKeys.length + '/' + keys.length + ' 처리, 나머지는 다음 프레임으로');
        break;
      }
      
      var key = keys[i];
      var item = dirtySet[key];
      if (!item) {
        processedKeys.push(key);
        continue;
      }
      
      var coin = item.coin;
      var rowId = 'row-' + coin.exchange + '-' + coin.symbol;
      var row = document.getElementById(rowId);
      
      if (row) {
        //  가상 스크롤: 행이 올바른 코인인지 확인
        // 스크롤로 인해 행이 재활용되었을 수 있으므로 dataset 검증
        if (row.dataset.symbol !== coin.symbol || row.dataset.exchangeId !== coin.exchange) {
          // 행이 다른 코인으로 재활용됨 - 깜빡임 스킵
          processedKeys.push(key);
          continue;
        }
        
        // 단일 코인 업데이트 (DOM Patching)
        updateSingleCoinRow(coin);
        
        //  깜빡임 효과 처리 (renderFrame 내부에서만!)
        // - throttle 적용: 500ms 간격
        //  행이 올바른 코인인지 재확인
        if (item.priceChanged && row.dataset.symbol === coin.symbol) {
          var flashKey = coin.exchange + ':' + coin.symbol;
          var lastFlash = flashLastTime[flashKey] || 0;
          
          if (now - lastFlash >= FLASH_THROTTLE_MS) {
            flashLastTime[flashKey] = now;
            
            // 기존 flash 클래스 제거 (reflow 없이)
            row.classList.remove('flash-up', 'flash-down');
            
            // 가격 변동 방향에 따라 클래스 추가
            if (coin.price > item.prevPrice) {
              row.classList.add('flash-up');
            } else if (coin.price < item.prevPrice) {
              row.classList.add('flash-down');
            }
            
            // 0.5초 후 클래스 제거 (별도 setTimeout)
            //  클로저로 심볼도 캡처하여 검증
            (function(r, sym) {
              setTimeout(function() {
                // 행이 아직 같은 코인인지 확인
                if (r.dataset.symbol === sym) {
                  r.classList.remove('flash-up', 'flash-down');
                }
              }, 500);
            })(row, coin.symbol);
          }
        }
      } else {
        // 행이 없으면 전체 렌더링 필요 (새 코인 추가 등)
        scheduleRenderTableFromTicker();
      }
      
      // 처리 완료된 키 기록
      processedKeys.push(key);
    }
    
    //  처리 완료된 키만 dirtySet에서 제거 (나머지는 유지)
    for (var j = 0; j < processedKeys.length; j++) {
      delete dirtySet[processedKeys[j]];
    }
    
    // 다음 프레임 예약 (남은 작업 또는 새 데이터 처리)
    requestAnimationFrame(renderFrame);
  }
  
  requestAnimationFrame(renderFrame);
}

// ---
// WebSocket 틱으로 인한 테이블 리렌더링 안전 스케줄링 (명세서 3-4)
// ---
var lastRenderTime = 0;
var RENDER_THROTTLE_MS = 100; // 100ms throttle (초당 10회 제한)

function scheduleRenderTableFromTicker() {
  // 사용자가 테이블 위에서 마우스를 누르고 있으면, 렌더링을 잠시 미룸
  if (isTableMouseDown) {
    tickerRenderPending = true;
    return;
  }

  // 이미 렌더링이 예약되어 있으면 중복으로 예약하지 않음
  if (tickerRenderPending) {
    return;
  }

  // Throttle: 마지막 렌더링 후 100ms 이내면 무시
  var now = Date.now();
  if (now - lastRenderTime < RENDER_THROTTLE_MS) {
    return;
  }

  tickerRenderPending = true;

  // 다음 브라우저 렌더링 프레임에서 한 번만 renderTable() 호출
  requestAnimationFrame(function () {
    tickerRenderPending = false;
    lastRenderTime = Date.now();
    renderTable();
  });
}

// [문제 2 해결] 단일 코인 빠른 업데이트 (전체 렌더링 없이 해당 행만 업데이트)
//  가상 스크롤: dataset 검증 추가
function updateSingleCoinRow(coin) {
  var rowId = 'row-' + coin.exchange + '-' + coin.symbol;
  var row = document.getElementById(rowId);
  
  if (!row) return false; // 행이 없으면 전체 렌더링 필요
  
  //  가상 스크롤: 행이 올바른 코인인지 확인
  if (row.dataset.symbol !== coin.symbol || row.dataset.exchangeId !== coin.exchange) {
    return false; // 행이 다른 코인으로 재활용됨
  }
  
  //  row.cells는 HTMLCollection으로 즉시 접근 가능 (querySelectorAll보다 훨씬 빠름)
  var cells = row.cells;
  if (cells.length < 6) return false;
  
  // 가격 업데이트 (셀 2)
  //  해외 거래소는 USDT 표시 포함
  var priceHtml = formatPriceWithCurrency(coin.price, coin.exchange);
  if (cells[2].innerHTML !== priceHtml) {
    cells[2].innerHTML = priceHtml;
  }
  
  // 24H 등락률 업데이트 (셀 3)
  var changeText = formatChange(coin.change24h);
  var changeClass = coin.change24h >= 0 ? 'change-positive' : 'change-negative';
  if (cells[3].textContent !== changeText) {
    cells[3].textContent = changeText;
  }
  if (cells[3].className !== changeClass) {
    cells[3].className = changeClass;
  }
  
  // ---
  //  상승/하락% 업데이트 (셀 4, 5) - 이원화 상태 처리
  // - undefined: 로딩 중 ("Calc...", prob-calc)
  // - null: 데이터 부족 ("-", prob-null)
  // - number: 정상 값 (N%, prob-high/medium/low)
  // ---
  var isMomentumSupported = isSupportedMomentumUnit(parseInt(currentMomentumTimeframe, 10));
  
  var upText, downText, upClass, downClass;
  
  if (isMomentumSupported) {
    //  상승확률 처리 - undefined 또는 'CALC' 문자열 체크
    if (coin.upProbability === undefined || coin.upProbability === 'CALC') {
      upText = 'Calc...';
      upClass = 'prob-calc';
    } else if (coin.upProbability === null) {
      upText = '-';
      upClass = 'prob-null';
    } else {
      upText = coin.upProbability + '%';
      upClass = getProbClass(coin.upProbability, 'up');
    }
    
    // 하락확률 처리
    if (coin.downProbability === undefined || coin.downProbability === 'CALC') {
      downText = 'Calc...';
      downClass = 'prob-calc';
    } else if (coin.downProbability === null) {
      downText = '-';
      downClass = 'prob-null';
    } else {
      downText = coin.downProbability + '%';
      downClass = getProbClass(coin.downProbability, 'down');
    }
    
    if (cells[4].textContent !== upText) cells[4].textContent = upText;
    if (cells[4].className !== upClass) cells[4].className = upClass;
    if (cells[5].textContent !== downText) cells[5].textContent = downText;
    if (cells[5].className !== downClass) cells[5].className = downClass;
  }
  
  return true;
}

// ---
// TradingView 심볼 결정 함수 (명세서 1-2)
//  심볼이 이제 짧은 형태(BTC)로 저장되므로 거래소별로 조합
// ---
function getTvSymbol(symbol, exchangeId) {
  //  비표준 심볼 검사 (한자, 한글 등 포함 시 차트 미지원)
  // 영문(a-z, A-Z), 숫자(0-9), 점(.), 하이픈(-) 외의 문자가 있으면 null 반환
  if (/[^a-zA-Z0-9.-]/.test(symbol)) {
    console.warn(' 비표준 심볼 감지 (차트 미지원):', symbol);
    return null;
  }
  
  var key = exchangeId + ':' + symbol;
  if (tvSymbolMap[key]) {
    return tvSymbolMap[key];
  }
  //  심볼이 이미 짧은 형태(BTC)이므로 직접 조합
  if (exchangeId === 'UPBIT_SPOT') {
    return 'UPBIT:' + symbol + 'KRW';
  } else if (exchangeId === 'BITHUMB_SPOT') {
    return 'BITHUMB:' + symbol + 'KRW';
  } else if (exchangeId === 'BINANCE_SPOT') {
    return 'BINANCE:' + symbol + 'USDT';
  } else if (exchangeId === 'BINANCE_FUTURES') {
    //  TradingView 선물 심볼 표준화: USDT.P (무기한 선물)
    return 'BINANCE:' + symbol + 'USDT.P';
  } else if (exchangeId === 'OKX_SPOT') {
    return 'OKX:' + symbol + 'USDT';
  } else if (exchangeId === 'OKX_FUTURES') {
    //  TradingView 선물 심볼 표준화: USDT.P (무기한 선물)
    return 'OKX:' + symbol + 'USDT.P';
  } else if (exchangeId === 'BYBIT_SPOT') {
    return 'BYBIT:' + symbol + 'USDT';
  } else if (exchangeId === 'BYBIT_FUTURES') {
    return 'BYBIT:' + symbol + 'USDT.P';
  }
  // 그 외는 업비트 기준 fallback
  return 'UPBIT:' + symbol + 'KRW';
}

// ---
// 거래 버튼 업데이트 함수 (명세서 4-3)
// ---
function updateTradeButtons(symbol, activeExchangeId) {
  var container = document.getElementById('desktopTradeButtons');
  if (!container) return;
  
  container.innerHTML = '';
  
  // 현재 활성화된 거래소에 대해서만 버튼 생성
  activeExchangesList.forEach(function(exchangeId) {
    var buildUrl = tradeUrls[exchangeId];
    if (!buildUrl) return;
    
    var a = document.createElement('a');
    a.href = buildUrl(symbol);
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.className = 'exchange-btn';
    a.dataset.exchangeId = exchangeId;
    a.innerHTML = getExchangeLabelWithEmoji(exchangeId);
    
    if (exchangeId === activeExchangeId) {
      a.classList.add('active');
    }
    
    container.appendChild(a);
  });
}

// ---
// 모바일 거래 버튼 업데이트 함수 (명세서 4-4)
// ---
function updateMobileTradeButtons(symbol, activeExchangeId) {
  var container = document.getElementById('mobileTradeButtons');
  if (!container) return;
  
  container.innerHTML = '';
  
  activeExchangesList.forEach(function(exchangeId) {
    var buildUrl = tradeUrls[exchangeId];
    if (!buildUrl) return;
    
    var a = document.createElement('a');
    a.href = buildUrl(symbol);
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.className = 'exchange-btn';
    a.dataset.exchangeId = exchangeId;
    a.innerHTML = getExchangeLabelWithEmoji(exchangeId);
    
    if (exchangeId === activeExchangeId) {
      a.classList.add('active');
    }
    
    container.appendChild(a);
  });
}

// ---
// 모바일 전체화면 차트 표시 (명세서 5-1)
// ---
function showMobileChart(symbol, exchangeId) {
  var tvSymbol = getTvSymbol(symbol, exchangeId);
  
  //  차트 미지원 심볼 처리 (한자, 한글 등 비표준 문자 포함)
  if (!tvSymbol) {
    console.warn(' 차트 미지원 심볼:', symbol, exchangeId);
    
    // 현재 선택 상태 저장 (심볼 정보는 유지)
    currentSymbol = symbol;
    currentExchangeId = exchangeId;
    selectedCoin = { exchange: exchangeId, symbol: symbol };
    
    // 모달 헤더 업데이트
    var symbolEl = document.getElementById('mobileChartSymbol');
    var exchangeEl = document.getElementById('mobileChartExchange');
    if (symbolEl) symbolEl.textContent = symbol;
    if (exchangeEl) {
      exchangeEl.textContent = getExchangeDisplayName(exchangeId);
      exchangeEl.className = 'exchange-tag ' + exchangeId;
    }
    
    // 차트 컨테이너에 미지원 메시지 표시
    var chartContainer = document.getElementById('mobile-tv-chart-container');
    if (chartContainer) {
      var unsupportedMsg = currentLang === 'ko' ? '차트 미지원 심볼' : 'Unsupported Symbol';
      var warningSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#888" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
      chartContainer.innerHTML = '<div style="display:flex; width:100%; height:100%; align-items:center; justify-content:center; color:#888; flex-direction:column; gap:10px; background:#1a1a2e;">' + warningSvg + '<span style="font-size:14px;">' + unsupportedMsg + '</span><span style="font-size:12px; color:#666;">(' + symbol + ')</span></div>';
    }
    
    // 모달 표시 (심볼명/거래소 정보는 보여줌)
    showMobileModal();
    updateMobileTradeButtons(symbol, exchangeId);
    renderTable();
    return;
  }
  
  // 현재 선택 상태 저장
  currentSymbol = symbol;
  currentExchangeId = exchangeId;
  selectedCoin = { exchange: exchangeId, symbol: symbol };
  
  // 모달 헤더 업데이트
  var symbolEl = document.getElementById('mobileChartSymbol');
  var exchangeEl = document.getElementById('mobileChartExchange');
  
  if (symbolEl) {
    symbolEl.textContent = symbol;
  }
  
  if (exchangeEl) {
    exchangeEl.textContent = getExchangeDisplayName(exchangeId);
    exchangeEl.className = 'exchange-tag ' + exchangeId;
  }
  
  // 차트 컨테이너
  var chartContainer = document.getElementById('mobile-tv-chart-container');
  if (!chartContainer) {
    console.warn('[showMobileChart] 차트 컨테이너 없음');
    return;
  }
  
  // ---
  //  위젯 재사용 로직 (Widget Reusability)
  // - 위젯이 이미 존재하면 setSymbol()로 종목만 즉시 교체
  // ---
  if (mobileTvWidget && typeof mobileTvWidget.activeChart === 'function') {
    try {
      console.log(' 모바일 기존 위젯 재사용 - setSymbol 호출:', tvSymbol);
      mobileTvWidget.activeChart().setSymbol(tvSymbol);
      // 모달 표시 및 거래 버튼 업데이트
      showMobileModal();
      updateMobileTradeButtons(symbol, exchangeId);
      renderTable();
      return;  // 위젯 재사용 성공 - 여기서 종료
    } catch (e) {
      console.warn(' 모바일 setSymbol 실패, 위젯 재생성 필요:', e.message);
      mobileTvWidget = null;
    }
  }
  
  // 위젯이 없거나 재사용 실패 → 새로 생성
  chartContainer.innerHTML = '';
  pendingMobileSymbol = tvSymbol;  // 대기 심볼 저장
  
  // ---
  //  ResizeObserver 기반 위젯 생성 (Deterministic Rendering)
  // ---
  if (mobileChartObserver) {
    mobileChartObserver.disconnect();
  }
  
  mobileChartObserver = new ResizeObserver(function(entries) {
    for (var i = 0; i < entries.length; i++) {
      var entry = entries[i];
      var rect = entry.contentRect;
      
      // 컨테이너 크기가 확정되었는지 확인 (최소 100x100)
      if (rect.width > 100 && rect.height > 100) {
        console.log(' 모바일 ResizeObserver: 컨테이너 크기 확정됨 -', rect.width + 'x' + rect.height);
        
        mobileChartObserver.disconnect();
        mobileChartObserver = null;
        
        if (pendingMobileSymbol) {
          createMobileWidget(pendingMobileSymbol);
          pendingMobileSymbol = null;
        }
        break;
      }
    }
  });
  
  mobileChartObserver.observe(chartContainer);
  console.log(' 모바일 ResizeObserver 시작 - 컨테이너 크기 감시 중...');
  
  // 모달 표시 (ResizeObserver가 크기 변화 감지하도록)
  showMobileModal();
  
  // 거래 버튼 업데이트
  updateMobileTradeButtons(symbol, exchangeId);
  
  // 테이블 선택 상태 갱신
  renderTable();
}

// ---
//  모바일 모달 표시 헬퍼 함수
// ---
function showMobileModal() {
  var modal = document.getElementById('mobileChartModal');
  if (modal) {
    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
    history.pushState({ mobileChart: true }, '');
  }
}

// ---
//  모바일 TradingView 위젯 생성 헬퍼 함수
// ---
function createMobileWidget(tvSymbol) {
  console.log(' createMobileWidget 호출 - 심볼:', tvSymbol);
  
  function doCreateWidget() {
    mobileTvWidget = new TradingView.widget({
      "container_id": "mobile-tv-chart-container",
      "symbol": tvSymbol,
      "interval": getTvIntervalFromMomentum(),
      "timezone": "Asia/Seoul",
      "theme": "dark",
      "style": "1",
      "locale": currentLang === 'ko' ? 'kr' : 'en',
      "toolbar_bg": "#1a1a2e",
      "enable_publishing": false,
      "hide_top_toolbar": true,
      "hide_legend": false,
      "save_image": false,
      "autosize": true,
      "width": "100%",
      "height": "100%",
      "studies": []
    });
    
    mobileTvWidget.onChartReady(function () {
      console.log('[TV Mobile] onChartReady 콜백 실행됨');
      
      //  차트 준비 완료 후 한 번만 resize 트리거
      window.dispatchEvent(new Event('resize'));
      
      var chart = mobileTvWidget.chart();
      if (!chart) {
        console.warn('[TV Mobile] chart() 메서드 없음 - 무료 위젯 제한일 수 있음');
        return;
      }
      
      if (!chart.onIntervalChanged) {
        console.warn('[TV Mobile] onIntervalChanged 메서드 없음 - 무료 위젯 제한일 수 있음');
        return;
      }

      console.log('[TV Mobile] onIntervalChanged 이벤트 구독 시작');
      chart.onIntervalChanged().subscribe(null, function (interval) {
        console.log('[TV Mobile] 분봉 변경 이벤트 수신:', interval);
        handleChartIntervalChanged(interval);
      });
      console.log('[TV Mobile] onIntervalChanged 이벤트 구독 완료');
    });
  }
  
  // tv.js 로드 확인
  if (typeof TradingView !== 'undefined' && tvScriptLoaded) {
    doCreateWidget();
  } else {
    var script = document.createElement('script');
    script.src = 'https://s3.tradingview.com/tv.js';
    script.onload = function() {
      tvScriptLoaded = true;
      doCreateWidget();
    };
    document.head.appendChild(script);
  }
}

// ---
// 모바일 차트 모달 닫기
// ---
function closeMobileChart() {
  var modal = document.getElementById('mobileChartModal');
  if (modal) {
    modal.classList.remove('active');
    //  배경 스크롤은 항상 hidden 유지 (단일 스크롤 소스)
    // 모달이 닫혀도 body 스크롤은 비활성화 상태 유지
    document.body.style.overflow = 'hidden';
  }
  
  // 모바일 위젯 정리 (명세서 3-7)
  if (mobileTvWidget && typeof mobileTvWidget.remove === 'function') {
    try {
      mobileTvWidget.remove();
    } catch (e) {
      console.warn('mobileTvWidget 제거 중 오류:', e);
    }
  }
  mobileTvWidget = null;
  
  // 차트 컨테이너 비우기 (메모리 정리)
  var chartContainer = document.getElementById('mobile-tv-chart-container');
  if (chartContainer) {
    chartContainer.innerHTML = '';
  }
}

// ---
// 코인 선택 통합 함수 (데스크톱/모바일 분기)
// ---
function selectCoin(symbol, exchangeId) {
  if (isMobile()) {
    showMobileChart(symbol, exchangeId);
  } else {
    showDesktopChart(symbol, exchangeId);
  }
}

// ---
// 차트 로딩 함수 (명세서 2-3)
// ---
function showDesktopChart(symbol, exchangeId) {
  var tvSymbol = getTvSymbol(symbol, exchangeId);
  
  //  차트 미지원 심볼 처리 (한자, 한글 등 비표준 문자 포함)
  if (!tvSymbol) {
    console.warn(' 차트 미지원 심볼:', symbol, exchangeId);
    
    // 현재 선택 상태 저장 (심볼 정보는 유지)
    currentSymbol = symbol;
    currentExchangeId = exchangeId;
    selectedCoin = { exchange: exchangeId, symbol: symbol };
    
    // 테이블 선택 상태 갱신
    renderTable();
    
    // placeholder 숨기고 차트 컨테이너에 미지원 메시지 표시
    var chartContainer = document.getElementById('tv-chart-container');
    var placeholder = document.querySelector('.chart-placeholder');
    
    if (placeholder) placeholder.style.display = 'none';
    if (chartContainer) {
      chartContainer.style.display = 'flex';
      var unsupportedMsg = currentLang === 'ko' ? '차트 미지원 심볼' : 'Unsupported Symbol';
      var unsupportedDesc = currentLang === 'ko' ? 'TradingView에서 지원하지 않는 심볼입니다' : 'This symbol is not supported by TradingView';
      var warningSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#888" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
      chartContainer.innerHTML = '<div style="display:flex; width:100%; height:100%; align-items:center; justify-content:center; color:#888; flex-direction:column; gap:10px; background:#1a1a2e;">' + warningSvg + '<span style="font-size:16px;">' + unsupportedMsg + '</span><span style="font-size:14px; color:#666;">(' + symbol + ')</span><span style="font-size:12px; color:#555;">' + unsupportedDesc + '</span></div>';
    }
    
    // 기존 위젯 참조 초기화
    tvWidget = null;
    
    // 거래 버튼은 업데이트 (거래는 가능)
    updateTradeButtons(symbol, exchangeId);
    return;
  }
  
  // 현재 선택 상태 저장
  currentSymbol = symbol;
  currentExchangeId = exchangeId;
  selectedCoin = { exchange: exchangeId, symbol: symbol };
  
  // 테이블 선택 상태 갱신
  renderTable();
  
  var chartContainer = document.getElementById('tv-chart-container');
  var placeholder = document.querySelector('.chart-placeholder');
  
  if (placeholder) {
    placeholder.style.display = 'none';
  }
  
  if (!chartContainer) {
    console.warn('[showDesktopChart] 차트 컨테이너 없음');
    return;
  }
  
  chartContainer.style.display = 'block';
  
  // ---
  //  위젯 재사용 로직 (Widget Reusability)
  // - 위젯이 이미 존재하면 setSymbol()로 종목만 즉시 교체
  // - 위젯을 새로 생성하지 않아 로딩 렉 대폭 감소
  // ---
  if (tvWidget && typeof tvWidget.activeChart === 'function') {
    try {
      console.log(' 기존 위젯 재사용 - setSymbol 호출:', tvSymbol);
      tvWidget.activeChart().setSymbol(tvSymbol);
      // 거래 버튼 업데이트
      updateTradeButtons(symbol, exchangeId);
      return;  // 위젯 재사용 성공 - 여기서 종료
    } catch (e) {
      console.warn(' setSymbol 실패, 위젯 재생성 필요:', e.message);
      // 실패 시 아래로 진행하여 위젯 재생성
      tvWidget = null;
    }
  }
  
  // 위젯이 없거나 재사용 실패 → 새로 생성
  chartContainer.innerHTML = '';
  pendingDesktopSymbol = tvSymbol;  // 대기 심볼 저장
  
  // ---
  //  ResizeObserver 기반 위젯 생성 (Deterministic Rendering)
  // - setTimeout 대신 ResizeObserver로 컨테이너 크기 확정 후 위젯 생성
  // - 컨테이너 크기가 0보다 커지면 위젯 생성 트리거
  // ---
  if (desktopChartObserver) {
    desktopChartObserver.disconnect();  // 기존 옵저버 해제
  }
  
  desktopChartObserver = new ResizeObserver(function(entries) {
    for (var i = 0; i < entries.length; i++) {
      var entry = entries[i];
      var rect = entry.contentRect;
      
      // 컨테이너 크기가 확정되었는지 확인 (최소 100x100)
      if (rect.width > 100 && rect.height > 100) {
        console.log(' ResizeObserver: 컨테이너 크기 확정됨 -', rect.width + 'x' + rect.height);
        
        // 옵저버 해제 (한 번만 실행)
        desktopChartObserver.disconnect();
        desktopChartObserver = null;
        
        // 대기 중인 심볼로 위젯 생성
        if (pendingDesktopSymbol) {
          createDesktopWidget(pendingDesktopSymbol);
          pendingDesktopSymbol = null;
        }
        break;
      }
    }
  });
  
  desktopChartObserver.observe(chartContainer);
  console.log(' ResizeObserver 시작 - 컨테이너 크기 감시 중...');
  
  // 거래 버튼 업데이트
  updateTradeButtons(symbol, exchangeId);
}

// ---
//  데스크톱 TradingView 위젯 생성 헬퍼 함수
// - ResizeObserver 콜백에서 호출됨
// ---
function createDesktopWidget(tvSymbol) {
  console.log(' createDesktopWidget 호출 - 심볼:', tvSymbol);
  
  // tv.js 스크립트 로드 (한 번만)
  function doCreateWidget() {
    tvWidget = new TradingView.widget({
      "container_id": "tv-chart-container",
      "symbol": tvSymbol,
      "interval": getTvIntervalFromMomentum(),
      "timezone": "Asia/Seoul",
      "theme": "dark",
      "style": "1",
      "locale": currentLang === 'ko' ? 'kr' : 'en',
      "toolbar_bg": "#1a1a2e",
      "enable_publishing": false,
      "hide_top_toolbar": false,
      "hide_legend": false,
      "save_image": false,
      "autosize": true,
      "width": "100%",
      "height": "100%",
      "studies": []
    });
    
    // TradingView 차트 준비 완료 후 이벤트 구독
    tvWidget.onChartReady(function () {
      console.log('[TV Desktop] onChartReady 콜백 실행됨');
      
      //  차트 준비 완료 후 한 번만 resize 트리거
      window.dispatchEvent(new Event('resize'));
      
      var chart = tvWidget.chart();
      if (!chart) {
        console.warn('[TV Desktop] chart() 메서드 없음 - 무료 위젯 제한일 수 있음');
        return;
      }
      
      if (!chart.onIntervalChanged) {
        console.warn('[TV Desktop] onIntervalChanged 메서드 없음 - 무료 위젯 제한일 수 있음');
        return;
      }

      console.log('[TV Desktop] onIntervalChanged 이벤트 구독 시작');
      chart.onIntervalChanged().subscribe(null, function (interval) {
        console.log('[TV Desktop] 분봉 변경 이벤트 수신:', interval);
        handleChartIntervalChanged(interval);
      });
      console.log('[TV Desktop] onIntervalChanged 이벤트 구독 완료');
    });
    
    if (currentViewMode === 'with-chart' && typeof updateMainLayoutHeight === 'function') {
      setTimeout(updateMainLayoutHeight, 100);
    }
  }
  
  // tv.js 로드 확인
  if (typeof TradingView !== 'undefined' && tvScriptLoaded) {
    doCreateWidget();
  } else {
    var script = document.createElement('script');
    script.src = 'https://s3.tradingview.com/tv.js';
    script.onload = function() {
      tvScriptLoaded = true;
      doCreateWidget();
    };
    document.head.appendChild(script);
  }
}

// ---
// 레이아웃 높이 계산
// ---
function updateMainLayoutHeight() {
  if (currentViewMode === 'list-only') return;
  
  var header = document.querySelector('.header');
  var filters = document.querySelector('.filters');
  var footer = document.querySelector('.footer');
  var mainLayout = document.querySelector('.main-layout');
  
  var headerHeight = header ? header.offsetHeight : 0;
  var filtersHeight = filters ? filters.offsetHeight : 0;
  var footerHeight = footer ? footer.offsetHeight : 0;
  var viewportHeight = window.innerHeight;
  
  var targetHeight = viewportHeight - headerHeight - filtersHeight - footerHeight;
  
  if (mainLayout) {
    mainLayout.style.height = targetHeight + 'px';
  }
}

// ---
// 레이아웃 모드 적용 함수
// ---
function applyViewMode(mode) {
  currentViewMode = mode;

  var htmlEl  = document.documentElement;
  var bodyEl  = document.body;
  var mainEl  = document.querySelector('.main-layout');

  var listBtn  = document.getElementById('viewListOnlyBtn');
  var chartBtn = document.getElementById('viewWithChartBtn');

  if (!mainEl) return;

  mainEl.classList.remove('view-list-only', 'view-with-chart');
  htmlEl.classList.remove('view-list-only', 'view-with-chart');
  bodyEl.classList.remove('view-list-only', 'view-with-chart');

  if (mode === 'list-only') {
    mainEl.classList.add('view-list-only');
    htmlEl.classList.add('view-list-only');
    bodyEl.classList.add('view-list-only');

    if (listBtn && chartBtn) {
      listBtn.classList.add('active');
      chartBtn.classList.remove('active');
    }
  } else {
    mainEl.classList.add('view-with-chart');
    htmlEl.classList.add('view-with-chart');
    bodyEl.classList.add('view-with-chart');

    if (listBtn && chartBtn) {
      chartBtn.classList.add('active');
      listBtn.classList.remove('active');
    }

    if (typeof updateMainLayoutHeight === 'function') {
      setTimeout(updateMainLayoutHeight, 50);
    }
    
    // ---
    //  ResizeObserver 기반 차트 리사이즈
    // - setTimeout 대신 컨테이너 크기 변화 감지 후 resize 트리거
    // - display: none → block 전환 시 캔버스 크기 재계산
    // ---
    if (tvWidget) {
      var chartContainer = document.getElementById('tv-chart-container');
      if (chartContainer) {
        var viewModeObserver = new ResizeObserver(function(entries) {
          for (var i = 0; i < entries.length; i++) {
            var rect = entries[i].contentRect;
            if (rect.width > 100 && rect.height > 100) {
              console.log(' applyViewMode ResizeObserver: 컨테이너 확정 -', rect.width + 'x' + rect.height);
              window.dispatchEvent(new Event('resize'));
              viewModeObserver.disconnect();
              break;
            }
          }
        });
        viewModeObserver.observe(chartContainer);
      }
    }
  }
}

// ---
// 모멘텀 버튼 UI 업데이트 (명세서 4-3)
// ---
function updateMomentumButtonsUI(unit) {
  var n = parseInt(unit, 10);
  console.log('[UI] updateMomentumButtonsUI 호출됨, unit:', unit, '-> n:', n);
  
  if (isNaN(n)) {
    console.warn('[UI] 유효하지 않은 unit:', unit);
    return;
  }
  
  var supported = isSupportedMomentumUnit(n);
  console.log('[UI] 지원 여부:', supported, '(SUPPORTED_MOMENTUM_UNITS:', SUPPORTED_MOMENTUM_UNITS.join(','), ')');

  var buttons = document.querySelectorAll('.momentum-btn');
  console.log('[UI] 발견된 모멘텀 버튼 개수:', buttons.length);
  
  buttons.forEach(function (btn) {
    var btnUnit = parseInt(btn.dataset.unit, 10);

    if (!supported) {
      // 지원되지 않는 분봉이 선택된 경우: 모든 버튼의 active 해제
      btn.classList.remove('active');
      return;
    }

    if (btnUnit === n) {
      btn.classList.add('active');
      console.log('[UI] 버튼 활성화:', btnUnit);
    } else {
      btn.classList.remove('active');
    }
  });
}

// ---
// 모멘텀 타임프레임 변경 (명세서 4-4 차트는 항상 전환, 모멘텀은 가능할 때만)
// ---
async function changeMomentumTimeframe(unit) {
  var num = parseInt(unit, 10);
  if (isNaN(num)) return;

  // 먼저 전역 상태와 버튼 UI를 갱신
  currentMomentumTimeframe = num;
  updateMomentumButtonsUI(num);

  var supported = isSupportedMomentumUnit(num);

  // 1) 차트 분봉은 모멘텀 계산 성공 여부와 관계없이 항상 최신 선택값을 따라가도록 함
  if (currentSymbol && currentExchangeId) {
    if (isMobile()) {
      var modal = document.getElementById('mobileChartModal');
      if (modal && modal.classList.contains('active')) {
        showMobileChart(currentSymbol, currentExchangeId);
      }
    } else {
      if (currentViewMode === 'with-chart') {
        showDesktopChart(currentSymbol, currentExchangeId);
      }
    }
  }

  // 2) 지원되지 않는 분봉 (예: 45분)인 경우
  //    - 서버에 모멘텀 재계산을 요청하지 않고
  //    - 테이블에서 상승/하락 컬럼만 '-'로 표시하도록 renderTable()을 호출한다.
  if (!supported) {
    renderTable();
    return;
  }

  // ════════════════════════════════════════════════════════════════
  //  캐시 있으면 즉시 표시! (Stale-While-Revalidate 패턴)
  // - 사용자 체감: 탭 전환 즉시 데이터 표시 (로딩 없음)
  // - 백그라운드: 서버에서 최신 데이터 받아서 조용히 갱신
  // ════════════════════════════════════════════════════════════════
  var cached = tfDataCache[num];
  if (cached && cached.coins && cached.coins.length > 0) {
    console.log('[TF] 캐시 히트! ' + num + '분 데이터 즉시 표시 (캐시 나이: ' + Math.round((Date.now() - cached.timestamp) / 1000) + '초)');
    
    // 캐시된 데이터로 즉시 렌더링
    coins = cached.coins;
    
    // ════════════════════════════════════════════════════════════════
    //  캐시 복원 시 coinIndexMap 재구축
    // ════════════════════════════════════════════════════════════════
    coinIndexMap = {};
    for (var ci = 0; ci < coins.length; ci++) {
      var c = coins[ci];
      coinIndexMap[c.exchange + ':' + c.symbol] = ci;
    }
    
    allFilteredCoins = getFilteredAndSortedCoins();
    
    // ════════════════════════════════════════════════════════════════
    //  filteredCoinIndexMap 재구축
    // ════════════════════════════════════════════════════════════════
    filteredCoinIndexMap = {};
    for (var fi = 0; fi < allFilteredCoins.length; fi++) {
      var fc = allFilteredCoins[fi];
      filteredCoinIndexMap[fc.exchange + ':' + fc.symbol] = fi;
    }
    
    // 가상 스크롤 렌더링
    var wrapper = document.getElementById('tableWrapper');
    var tbody = document.getElementById('coinTableBody');
    if (wrapper && tbody && typeof renderVirtualRows === 'function') {
      renderVirtualRows(wrapper, tbody);
    }
    
    // UI 깜빡임 없이 즉시 표시됨!
  } else {
    console.log('[TF] 캐시 미스. ' + num + '분 데이터 서버에서 로딩 중...');
  }

  // ════════════════════════════════════════════════════════════════
  //  타임프레임 변경 → WebSocket 메시지로 전송
  // - 기존: /api/momentum-timeframe 호출 (전역 변수 변경)
  // - 수정: WebSocket setTimeframe 메시지 (클라이언트별 독립 관리)
  //  Request ID 패턴 추가 - stale response 필터링
  //  캐시 유무와 관계없이 항상 최신 데이터 요청 (백그라운드 갱신)
  // ════════════════════════════════════════════════════════════════
  try {
    //  Request ID 증가 - 매 요청마다 고유 ID 부여
    tfRequestId++;
    var thisRequestId = tfRequestId;
    console.log('[TF] 타임프레임 변경 요청: ' + num + '분, requestId=' + thisRequestId);
    
    // WebSocket으로 타임프레임 변경 요청 (requestId 포함)
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ 
        type: 'setTimeframe', 
        timeframe: num,
        requestId: thisRequestId  //  요청 ID 포함
      }));
    }
    
    // 서버 API도 호출 (캐시 갱신 트리거용)
    fetch('/api/momentum-timeframe?unit=' + num).catch(function() {});
    
    //  캐시 있으면 fetchCoinsWithUpdate 스킵 (이미 화면에 표시됨)
    // 서버 응답은 WebSocket refresh 메시지로 받아서 처리
    if (!cached || !cached.coins || cached.coins.length === 0) {
      // 캐시 없을 때만 약간의 대기 후 코인 데이터 갱신
      await new Promise(function(resolve) { setTimeout(resolve, 100); });
      await fetchCoinsWithUpdate();
    }
  } catch (error) {
    console.error('타임프레임 변경 실패:', error);
  }
}

// ---
// TradingView 차트에서 분봉 변경 시 호출되는 공통 처리 함수 (수정 3: 단방향)
// ---
function handleChartIntervalChanged(interval) {
  console.log('[Chart] 분봉 변경 감지:', interval, '(리스트에는 영향 없음 - 단방향 구조)');
  // 수정 3: 차트 분봉 변경은 차트만 바꾸고, 모멘텀 기준(리스트 정렬)에는 영향을 주지 않음
  // 모멘텀 버튼 UI도 건드리지 않음 - 사용자가 직접 버튼을 클릭해야만 리스트가 변경됨
}

// ---
// 코인 데이터 fetch
//  타임프레임 파라미터 추가
// ---
async function fetchCoinsWithUpdate() {
  try {
    //  현재 선택된 타임프레임으로 데이터 요청
    var tf = currentMomentumTimeframe || 240;
    var response = await fetch('/api/coins?tf=' + tf);
    var data = await response.json();
    coins = data;
    
    // ════════════════════════════════════════════════════════════════
    //  coinIndexMap 재구축
    // ════════════════════════════════════════════════════════════════
    coinIndexMap = {};
    for (var ci = 0; ci < coins.length; ci++) {
      var c = coins[ci];
      coinIndexMap[c.exchange + ':' + c.symbol] = ci;
    }
    
    //  서버 순위 유지: renderTable() 대신 filterCoins + renderVirtualRows 사용
    // renderTable()을 호출하면 getFilteredAndSortedCoins()가 클라이언트 정렬을 수행해서
    // 서버에서 보낸 타임프레임별 순위가 무시됨
    allFilteredCoins = filterCoins(coins);
    
    // ════════════════════════════════════════════════════════════════
    //  filteredCoinIndexMap 재구축
    // ════════════════════════════════════════════════════════════════
    filteredCoinIndexMap = {};
    for (var fi = 0; fi < allFilteredCoins.length; fi++) {
      var fc = allFilteredCoins[fi];
      filteredCoinIndexMap[fc.exchange + ':' + fc.symbol] = fi;
    }
    
    // 가상 스크롤 렌더링
    var wrapper = document.querySelector('.coin-table-wrapper');
    var tbody = document.getElementById('coinTableBody');
    if (wrapper && tbody) {
      renderVirtualRows(wrapper, tbody);
    }
  } catch (error) {
    console.error('코인 데이터 로드 실패:', error);
  }
}

// ---
// WebSocket 연결
// ---
function connectWebSocket() {
  var protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(protocol + '//' + window.location.host);
  
  ws.onopen = function() {
    console.log('WebSocket 연결됨');
    
    // ════════════════════════════════════════════════════════════════
    //  WebSocket 연결 시 현재 UI 타임프레임을 서버에 알림
    // - 서버 기본값과 UI 기본값이 다를 수 있으므로 동기화 필수!
    //  초기 동기화에도 requestId 포함
    // ════════════════════════════════════════════════════════════════
    if (currentMomentumTimeframe) {
      tfRequestId++;
      ws.send(JSON.stringify({ 
        type: 'setTimeframe', 
        timeframe: currentMomentumTimeframe,
        requestId: tfRequestId
      }));
      console.log('[WS] 초기 타임프레임 동기화:', currentMomentumTimeframe + '분, requestId=' + tfRequestId);
    }
    
    //  렌더링 루프 시작
    startRenderLoop();
  };
  
  ws.onmessage = function(event) {
    try {
      var message = JSON.parse(event.data);
      
      // ---
      //  순위표 스트리밍 프로토콜
      // - Type A ("U"): 보이는 코인 상세 정보 (실시간)
      // - Type B ("R"): 전체 순위표 (5초마다)
      // - initial: 최초 연결 시 전체 데이터
      // ---
      
      //  배열 형태인지 확인 (Type A, Type B)
      if (Array.isArray(message)) {
        var msgType = message[0];
        
        // ---
        // Type A: 보이는 코인 상세 정보 업데이트
        // 형식: ["U", "UPBIT_SPOT:BTC", price, change, up, down]
        // ---
        if (msgType === 'U') {
          var key = message[1];           // "UPBIT_SPOT:BTC"
          var parts = key.split(':');
          var exchange = parts[0];
          var symbol = parts[1];
          var price = message[2];
          var change24h = message[3];
          var upProbability = message[4];
          var downProbability = message[5];
          
          // ════════════════════════════════════════════════════════════════
          //  O(1) 코인 조회 (기존 O(N) 루프 제거)
          // - coinIndexMap[key]로 즉시 인덱스 접근
          // - 효과: 200개 코인 기준 200번 비교 → 1번 해시 조회
          // ════════════════════════════════════════════════════════════════
          var index = coinIndexMap[key];
          if (index === undefined) index = -1;
          
          var prevPrice = 0;
          if (index >= 0) {
            prevPrice = coins[index].price;
            coins[index].price = price;
            coins[index].change24h = change24h;
            coins[index].upProbability = upProbability;
            coins[index].downProbability = downProbability;
          }
          
          // 탭이 숨겨져 있으면 DOM 갱신 스킵
          if (!isPageVisible) {
            return;
          }
          
          // ════════════════════════════════════════════════════════════════
          //  O(1) 필터된 코인 인덱스 조회 (기존 O(N) 루프 제거)
          // ════════════════════════════════════════════════════════════════
          var coinIndexInFiltered = filteredCoinIndexMap[key];
          if (coinIndexInFiltered === undefined) coinIndexInFiltered = -1;
          
          // 범위 밖이면 DOM 갱신 스킵
          if (coinIndexInFiltered === -1 || 
              coinIndexInFiltered < virtualScrollState.startIndex || 
              coinIndexInFiltered >= virtualScrollState.endIndex) {
            return;
          }
          
          // dirtySet에 추가하여 렌더링 루프에서 처리
          var dirtyKey = exchange + ':' + symbol;
          dirtySet[dirtyKey] = {
            coin: coins[index],
            prevPrice: prevPrice,
            priceChanged: (prevPrice > 0 && price !== prevPrice)
          };
          
          if (!renderLoopRunning) {
            startRenderLoop();
          }
          return;
        }
        
        // ---
        // Type B: 전체 순위표 수신 (정렬 동기화)
        //  형식 변경: ["R", timeframe, "UPBIT_SPOT:BTC", ...]
        //  형식 변경: ["R", timeframe, requestId?, "UPBIT_SPOT:BTC", ...]
        // - 이전 형식: ["R", "UPBIT_SPOT:BTC", ...] (하위 호환 유지)
        // ---
        if (msgType === 'R') {
          // ════════════════════════════════════════════════════════════════
          //  R 메시지 타임프레임 체크 - Stale R 메시지 필터링
          //  R 메시지 requestId 체크 추가 - 동일 TF 재클릭 시 stale 필터링
          // ════════════════════════════════════════════════════════════════
          var rTimeframe = null;
          var rRequestId = null;
          var rankingStartIndex = 1;  // 기본: message[1]부터 코인 키
          
          //  새 형식 감지: message[1]이 숫자면 timeframe
          if (typeof message[1] === 'number') {
            rTimeframe = message[1];
            rankingStartIndex = 2;  // 기본: message[2]부터 코인 키
            
            //  requestId 감지: message[2]도 숫자면 requestId
            if (typeof message[2] === 'number') {
              rRequestId = message[2];
              rankingStartIndex = 3;  // message[3]부터 코인 키
            }
            
            // 현재 타임프레임과 다르면 무시!
            if (rTimeframe !== currentMomentumTimeframe) {
              console.log('[WS] 다른 TF의 R 메시지 무시! R의 TF=' + rTimeframe + '분, 현재 TF=' + currentMomentumTimeframe + '분');
              return;
            }
            
            //  requestId 체크 - 동일 TF라도 이전 요청의 R 메시지면 무시!
            // - rRequestId가 null이면 브로드캐스트 메시지 → 무조건 처리
            // - rRequestId가 있으면 사용자 요청 응답 → tfRequestId와 비교
            if (rRequestId !== null && rRequestId !== tfRequestId) {
              console.log('[WS] Stale R 메시지 무시! R.requestId=' + rRequestId + ', 현재 tfRequestId=' + tfRequestId + ', TF=' + rTimeframe + '분');
              return;
            }
          }
          //  하위 호환: message[1]이 문자열이면 구 형식 (timeframe 없음)
          // → 그대로 처리 (무시하지 않음)
          
          // ---
          //  WebSocket R 메시지 정렬 충돌 방지
          // - 서버 순서(모멘텀)와 사용자 정렬(24H 등) 충돌 해결
          // - 사용자 정렬 중이면 서버 순서 무시
          // ---
          
          // 1. 서버가 보낸 키 리스트로 coins 배열 갱신 (데이터 동기화)
          var rankingKeys = message.slice(rankingStartIndex);  //  시작 인덱스 변경
          var coinMap = {};
          for (var i = 0; i < coins.length; i++) {
            var c = coins[i];
            coinMap[c.exchange + ':' + c.symbol] = c;
          }
          
          var sortedCoins = [];
          for (var j = 0; j < rankingKeys.length; j++) {
            var rKey = rankingKeys[j];
            if (coinMap[rKey]) {
              sortedCoins.push(coinMap[rKey]);
              delete coinMap[rKey];
            }
          }
          // 순위표에 없는 나머지 코인들 뒤에 붙이기
          for (var leftoverKey in coinMap) {
             if (coinMap.hasOwnProperty(leftoverKey)) sortedCoins.push(coinMap[leftoverKey]);
          }
          
          // 원본 데이터 최신화
          coins = sortedCoins;
          
          // ════════════════════════════════════════════════════════════════
          //  coinIndexMap 재구축 (coins 배열 변경 시)
          // ════════════════════════════════════════════════════════════════
          coinIndexMap = {};
          for (var ci = 0; ci < coins.length; ci++) {
            var c = coins[ci];
            coinIndexMap[c.exchange + ':' + c.symbol] = ci;
          }

          //  정렬 충돌 방지 로직
          // 사용자가 정렬(컬럼 클릭 or 드롭다운)을 사용 중인지 확인
          var isUserSorting = (columnSortState.key !== null) || 
                              (document.getElementById('sortFilter').value !== 'default');

          if (isUserSorting) {
             // A. 사용자 정렬 중이면 -> 클라이언트 기준 재정렬 (서버 순서 무시)
             allFilteredCoins = getFilteredAndSortedCoins();
          } else {
             // B. 기본 상태면 -> 서버가 준 순서(모멘텀) 그대로 사용
             if (typeof filterCoins === 'function') {
                allFilteredCoins = filterCoins(coins);
             } else {
                allFilteredCoins = getFilteredAndSortedCoins(); // fallback
             }
          }
          
          // ════════════════════════════════════════════════════════════════
          //  filteredCoinIndexMap 재구축 (allFilteredCoins 변경 시)
          // ════════════════════════════════════════════════════════════════
          filteredCoinIndexMap = {};
          for (var fi = 0; fi < allFilteredCoins.length; fi++) {
            var fc = allFilteredCoins[fi];
            filteredCoinIndexMap[fc.exchange + ':' + fc.symbol] = fi;
          }

          // 화면 갱신
          if (isPageVisible && virtualScrollState.startIndex >= 0) {
            var wrapper = document.querySelector('.coin-table-wrapper');
            var tbody = document.getElementById('coinTableBody');
            if (wrapper && tbody && typeof renderVirtualRows === 'function') {
              renderVirtualRows(wrapper, tbody);
            }
          }
          return;
        }
      }
      
      // ---
      // 초기 데이터 (최초 연결 시)
      // 형식: { type: 'initial', data: [[exchange, symbol, price, up, down, change], ...], usdtKrwRate: number }
      //  초기 데이터도 캐시에 저장
      // ---
      if (message.type === 'initial') {
        //  clientId 저장
        if (message.clientId) {
          myClientId = message.clientId;
          console.log('🆔 clientId 수신:', myClientId);
        }
        
        //  환율 정보 저장
        if (message.usdtKrwRate) {
          usdtKrwRate = message.usdtKrwRate;
          console.log('[RATE] 환율 수신: 1 USDT = ' + usdtKrwRate.toLocaleString() + ' KRW');
        }
        
        //  채팅 히스토리 로드
        if (message.chatHistory && Array.isArray(message.chatHistory)) {
          message.chatHistory.forEach(function(msg) {
            addChatMessage(msg, true);  // skipBadge = true
          });
          console.log('[CHAT] 채팅 히스토리 로드: ' + message.chatHistory.length + '개');
        }
        
        coins = message.data.map(function(arr) {
          return {
            exchange: arr[0],
            symbol: arr[1],
            price: arr[2],
            upProbability: arr[3],
            downProbability: arr[4],
            change24h: arr[5]
          };
        });
        
        // ════════════════════════════════════════════════════════════════
        //  초기 데이터 로딩 시 coinIndexMap 구축
        // ════════════════════════════════════════════════════════════════
        coinIndexMap = {};
        for (var ci = 0; ci < coins.length; ci++) {
          var c = coins[ci];
          coinIndexMap[c.exchange + ':' + c.symbol] = ci;
        }
        
        // ════════════════════════════════════════════════════════════════
        //  초기 데이터를 현재 TF 캐시에 저장
        // - 페이지 로딩 후 TF 재클릭 시 즉시 표시 가능
        // ════════════════════════════════════════════════════════════════
        var initialTf = currentMomentumTimeframe || 1;
        if (tfDataCache.hasOwnProperty(initialTf)) {
          tfDataCache[initialTf] = {
            coins: coins.slice(),
            timestamp: Date.now()
          };
          console.log('[WS] 초기 데이터 TF ' + initialTf + '분 캐시 저장 (' + coins.length + '개 코인)');
        }
        
        renderTable();
        
        // ════════════════════════════════════════════════════════════════
        //  프리페칭 시작 - 모든 TF 데이터 백그라운드 로드
        // - 초기 데이터 수신 후 2초 대기 (페이지 렌더링 완료 대기)
        // - 그 후 1.5초 간격으로 나머지 TF 데이터 순차 요청
        // - 효과: 어떤 TF 버튼 클릭해도 즉시 표시!
        // ════════════════════════════════════════════════════════════════
        setTimeout(function() {
          console.log('[Prefetch] 초기 로딩 완료, 프리페칭 시작...');
          startPrefetching();
        }, PREFETCH_DELAY);
      }
      
      // ════════════════════════════════════════════════════════════════
      //  타임프레임 변경 시 전체 데이터 새로고침
      // - 형식: { type: 'refresh', data: [[exchange, symbol, price, up, down, change], ...], timeframe: number }
      // - 타임프레임 버튼 클릭 즉시 상승%/하락% 값이 갱신됨!
      //  Request ID 패턴 + Last Value Fallback 추가
      // - requestId 불일치 시 stale response 무시
      // - undefined/CALC 값은 마지막 알려진 값으로 대체 (정렬 유지)
      //  TF 체크 추가 - 브로드캐스트 지연 도착 시 방어
      //  TF별 전체 데이터 캐싱 추가
      //  프리페칭 지원 - 캐시 저장을 먼저 하고, 화면 갱신만 조건부로
      // ════════════════════════════════════════════════════════════════
      if (message.type === 'refresh') {
        var responseTf = message.timeframe || '?';
        var responseRequestId = message.requestId;
        
        console.log('[WS] 타임프레임 ' + responseTf + '분 데이터 수신 (requestId=' + responseRequestId + ')');
        
        // ════════════════════════════════════════════════════════════════
        //  1단계: 먼저 데이터 처리 (캐시 저장을 위해)
        // - 프리페칭 응답도 캐시에 저장해야 하므로 TF 체크 전에 처리!
        // ════════════════════════════════════════════════════════════════
        var processedCoins = message.data.map(function(arr) {
          var coin = {
            exchange: arr[0],
            symbol: arr[1],
            price: arr[2],
            upProbability: arr[3],
            downProbability: arr[4],
            change24h: arr[5]
          };
          
          //  Last Value Fallback - 정렬 붕괴 방지
          var momentumKey = coin.exchange + ':' + coin.symbol;
          var up = coin.upProbability;
          var down = coin.downProbability;
          
          // 값이 없거나 'CALC'면 캐시에서 복원
          if (up === undefined || up === null || up === 'CALC' ||
              down === undefined || down === null || down === 'CALC') {
            var cached = lastKnownMomentum[momentumKey];
            if (cached && cached.up !== undefined) {
              coin.upProbability = cached.up;
              coin.downProbability = cached.down;
            }
          } else {
            // 유효한 새 값이면 캐시에 저장
            lastKnownMomentum[momentumKey] = {
              up: up,
              down: down
            };
          }
          
          return coin;
        });
        
        // ════════════════════════════════════════════════════════════════
        //  2단계: 캐시 저장 (항상! - 프리페칭 데이터도 저장)
        // - 나중에 이 TF 버튼 클릭 시 즉시 표시 가능
        // ════════════════════════════════════════════════════════════════
        if (typeof responseTf === 'number' && tfDataCache.hasOwnProperty(responseTf)) {
          tfDataCache[responseTf] = {
            coins: processedCoins.slice(),  // 복사본 저장
            timestamp: Date.now()
          };
          console.log('[WS] TF ' + responseTf + '분 캐시 저장 완료 (' + processedCoins.length + '개 코인)');
        }
        
        // ════════════════════════════════════════════════════════════════
        //  3단계: 화면 갱신 여부 결정
        // - 현재 TF와 다르면 화면 갱신 스킵 (캐시만 저장하고 끝)
        // - 이게 프리페칭이 작동하는 핵심!
        // ════════════════════════════════════════════════════════════════
        if (typeof responseTf === 'number' && responseTf !== currentMomentumTimeframe) {
          console.log('[WS] 🔄 프리페칭 완료: ' + responseTf + '분 (현재 ' + currentMomentumTimeframe + '분, 화면 갱신 스킵)');
          return;
        }
        
        //  Request ID 체크 - Stale Response 필터링
        // - 빠른 TF 전환 시 이전 요청의 응답이 나중에 도착할 수 있음
        if (responseRequestId !== undefined && responseRequestId !== tfRequestId) {
          console.log('[WS] Stale response 무시! 응답 requestId=' + responseRequestId + ', 현재 tfRequestId=' + tfRequestId + ', TF=' + responseTf + '분');
          return;
        }
        
        // ════════════════════════════════════════════════════════════════
        //  4단계: 화면 갱신 (현재 TF와 일치할 때만)
        // ════════════════════════════════════════════════════════════════
        
        // 전역 coins 배열 갱신
        coins = processedCoins;
        
        // ════════════════════════════════════════════════════════════════
        //  coinIndexMap 재구축
        // ════════════════════════════════════════════════════════════════
        coinIndexMap = {};
        for (var ci = 0; ci < coins.length; ci++) {
          var c = coins[ci];
          coinIndexMap[c.exchange + ':' + c.symbol] = ci;
        }
        
        // 필터 + 정렬 적용 후 가상 스크롤 렌더링
        allFilteredCoins = getFilteredAndSortedCoins();
        
        // ════════════════════════════════════════════════════════════════
        //  filteredCoinIndexMap 재구축
        // ════════════════════════════════════════════════════════════════
        filteredCoinIndexMap = {};
        for (var fi = 0; fi < allFilteredCoins.length; fi++) {
          var fc = allFilteredCoins[fi];
          filteredCoinIndexMap[fc.exchange + ':' + fc.symbol] = fi;
        }
        
        var wrapper = document.querySelector('.coin-table-wrapper');
        var tbody = document.getElementById('coinTableBody');
        if (wrapper && tbody) {
          renderVirtualRows(wrapper, tbody);
        }
        
        console.log('[WS] 화면 갱신 완료 (' + coins.length + '개 코인)');
      }
      
      // ---
      //  환율 변경 메시지
      // 형식: { type: 'rate', usdtKrwRate: number }
      // ---
      if (message.type === 'rate') {
        usdtKrwRate = message.usdtKrwRate;
        console.log('[RATE] 환율 변경: 1 USDT = ' + usdtKrwRate.toLocaleString() + ' KRW');
        // 테이블 재렌더링 (원화 환산가 갱신)
        renderTable();
      }
      
      // ---
      //  채팅 메시지 처리
      // ---
      if (message.type === 'chat' || message.type === 'admin') {
        addChatMessage(message);
      }
      
      //  시스템 메시지 처리 (관리자 모드 활성화 포함)
      if (message.type === 'system') {
        // 관리자 모드 활성화 메시지 감지
        if (message.adminMode === true) {
          chatAdminMode = true;
          console.log('[Admin] 관리자 모드 활성화됨');
        }
        addChatMessage(message);
      }
      
      //  채팅 메시지 삭제 처리 (흔적 없이 삭제)
      if (message.type === 'chat_remove' && message.messageId) {
        var targetDiv = document.querySelector('.chat-message[data-msg-id="' + message.messageId + '"]');
        if (targetDiv) {
          targetDiv.remove();  // DOM에서 완전 제거
        }
      }
      
      //  채팅 메시지 업데이트 처리 (삭제 문구 표시)
      if (message.type === 'chat_update' && message.id) {
        var targetDiv = document.querySelector('.chat-message[data-msg-id="' + message.id + '"]');
        if (targetDiv) {
          // 삭제 문구로 교체
          var stubText = message.stubText || t('chat.deletedBySelf');
          targetDiv.innerHTML = '<span class="deleted-stub">' + escapeHtml(stubText) + '</span>';
          targetDiv.classList.add('chat-message-deleted');
          // 우클릭 및 롱프레스 이벤트 제거 (삭제된 메시지는 컨텍스트 메뉴 불필요)
          targetDiv.oncontextmenu = null;
          targetDiv.ontouchstart = null;
          targetDiv.ontouchend = null;
          targetDiv.ontouchmove = null;
          targetDiv.ontouchcancel = null;
        }
      }
      
      //  접속자 수 (UI 숨김 처리됨)
      if (message.type === 'count') {
        var countEl = document.getElementById('chatUserCount');
        if (countEl) {
          // countEl.textContent = message.count + ' online';
          // countEl.style.display = 'inline';
        }
      }
      
    } catch (error) {
      console.error('WebSocket 메시지 처리 오류:', error);
    }
  };
  
  ws.onclose = function() {
    // ════════════════════════════════════════════════════════════════
    //  재연결 폭풍(Reconnection Storm) 방지
    // - 서버 재시작 시 1,000명이 동시에 재연결하면 서버 마비
    // - 3초~5초 사이 랜덤 지연으로 연결 분산
    // ════════════════════════════════════════════════════════════════
    var delay = 3000 + Math.floor(Math.random() * 2000);
    console.log('WebSocket 연결 종료 - ' + (delay / 1000).toFixed(1) + '초 후 재연결');
    setTimeout(connectWebSocket, delay);
  };
  
  ws.onerror = function(error) {
    console.error('WebSocket 오류:', error);
  };
}

// ---
// 리사이저 설정 (명세서 3-2 pointer 이벤트 기반)
// ---
(function setupResizer() {
  var resizer = document.getElementById('resizer');
  var mainLayout = document.querySelector('.main-layout');
  var coinListPanel = document.getElementById('coinListPanel');
  var chartPanel = document.getElementById('chartPanel');

  if (!resizer || !mainLayout || !coinListPanel || !chartPanel) return;

  var isResizing = false;

  resizer.addEventListener('pointerdown', function(e) {
    isResizing = true;
    resizer.setPointerCapture(e.pointerId);
    document.body.classList.add('resizing');
  });

  resizer.addEventListener('pointermove', function(e) {
    if (!isResizing) return;

    var rect = mainLayout.getBoundingClientRect();
    var containerWidth = rect.width;
    var mouseX = e.clientX - rect.left;

    var leftPercent = (mouseX / containerWidth) * 100;
    leftPercent = Math.max(35, Math.min(75, leftPercent));
    var rightPercent = 100 - leftPercent;

    coinListPanel.style.flex = '0 0 ' + leftPercent + '%';
    chartPanel.style.flex = '0 0 ' + rightPercent + '%';
  });

  var stopResize = function(e) {
    if (!isResizing) return;
    isResizing = false;
    try {
      resizer.releasePointerCapture(e.pointerId);
    } catch (err) {
      // pointerId 없을 수 있음
    }
    document.body.classList.remove('resizing');

    // TradingView autosize 재계산
    window.dispatchEvent(new Event('resize'));
    setTimeout(function() {
      window.dispatchEvent(new Event('resize'));
    }, 200);
  };

  resizer.addEventListener('pointerup', stopResize);
  resizer.addEventListener('pointercancel', stopResize);
})();

// ---
// 이벤트 리스너 등록
// ---

// 거래소 필터 체크박스 변경 시 테이블 갱신 (명세서 1-3)
// - 라벨 클릭 시 브라우저 기본 동작(체크박스 토글)만 사용
// - 수동 토글 제거로 더블 토글 버그 해결
document.querySelectorAll('#exchangeFilterGroup [data-exchange-filter]').forEach(function(label) {
  var checkbox = label.querySelector('input[type="checkbox"]');
  if (!checkbox) return;

  // 체크박스 상태 변경 시 테이블/버튼 상태 갱신
  checkbox.addEventListener('change', function () {
    renderTable();
    
    //  필터 설정을 localStorage에 저장
    var activeExchanges = getActiveExchangeIds();
    SafeStorage.setItem('activeExchanges', JSON.stringify(activeExchanges));
    console.log(' 필터 설정 저장:', activeExchanges);
  });

  // 라벨 클릭 시에는 브라우저 기본 동작(체크박스 토글)만 사용
  // 여기에서는 별도의 수동 토글을 하지 않는다.
  label.addEventListener('click', function (e) {
    if (e.target.tagName === 'INPUT') {
      // input 자체를 클릭한 경우: change 이벤트에서 이미 처리됨
      return;
    }
    // 라벨 클릭 시 별도 처리 없음 (브라우저가 input 상태를 토글하고,
    // 그에 따라 change 이벤트가 발생하면서 renderTable()이 호출된다)
  });
});

//  정렬 드롭다운 - handleDropdownChange 사용
document.getElementById('sortFilter').addEventListener('change', handleDropdownChange);

// ---
//  검색창 이벤트 핸들러
// - input: 검색어 변경 시 즉시 필터링
// ---
(function initSearchInput() {
  var searchInput = document.getElementById('searchInput');
  if (!searchInput) return;
  
  // 입력 시 검색어 적용
  searchInput.addEventListener('input', function() {
    // 대소문자 무시, 공백 완전 제거 (명세서 수정: trim -> replace)
    searchKeyword = this.value.toUpperCase().replace(/\s/g, '');
    
    // Cookie Consent 확인 후 저장
    var consent = SafeStorage.getItem('cookieConsent');
    if (consent === 'all') {
      SafeStorage.setItem('last_search', searchKeyword);
    }
    
    console.log('[SEARCH] 검색어 변경: "' + searchKeyword + '"');
    renderTable();
  });
})();

// ---
//  즐겨찾기 초기화
// ---
initFavorites();

// ---
//  검색어 복원 (Cookie Consent 확인)
// ---
(function restoreSearchKeyword() {
  var consent = SafeStorage.getItem('cookieConsent');
  if (consent === 'all') {
    var savedSearch = SafeStorage.getItem('last_search');
    if (savedSearch) {
      searchKeyword = savedSearch;
      var searchInput = document.getElementById('searchInput');
      if (searchInput) {
        searchInput.value = savedSearch;
        console.log('[SEARCH] 저장된 검색어 복원: "' + savedSearch + '"');
      }
    }
  }
})();

//  통화 필터 이벤트 핸들러
document.getElementById('currencyFilter').addEventListener('change', function() {
  currentCurrencyMode = this.value;
  SafeStorage.setItem('currencyMode', currentCurrencyMode);
  console.log('[RATE] 통화 모드 변경: ' + currentCurrencyMode);
  renderTable();
});

//  통화 모드 초기화 (localStorage 또는 자동 감지)
(function initCurrencyMode() {
  var savedMode = SafeStorage.getItem('currencyMode');
  if (savedMode) {
    currentCurrencyMode = savedMode;
    console.log('[RATE] 저장된 통화 모드 복원: ' + currentCurrencyMode);
  } else {
    // 자동 감지: 브라우저 타임존 확인
    try {
      var timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
      if (timezone === 'Asia/Seoul') {
        currentCurrencyMode = 'KRW';
        console.log('[RATE] 자동 감지: 한국 타임존 → KRW 모드');
      } else {
        currentCurrencyMode = 'USDT';
        console.log('[RATE] 자동 감지: 해외 타임존 (' + timezone + ') → USDT 모드');
      }
    } catch (e) {
      currentCurrencyMode = 'ORIGINAL';
      console.log('[RATE] 자동 감지 실패 → ORIGINAL 모드');
    }
  }
  // 셀렉트 박스 동기화
  var select = document.getElementById('currencyFilter');
  if (select) {
    select.value = currentCurrencyMode;
  }
})();

//  컬럼 헤더 클릭 정렬 이벤트 등록
document.querySelectorAll('thead th[data-sort-key]').forEach(function(th) {
  th.addEventListener('click', function() {
    var key = this.getAttribute('data-sort-key');
    if (key) {
      handleColumnHeaderClick(key);
    }
  });
});

// 모멘텀 버튼
document.querySelectorAll('.momentum-btn').forEach(function(btn) {
  btn.addEventListener('click', function() {
    changeMomentumTimeframe(this.dataset.unit);
  });
});

// 레이아웃 토글 버튼
var listOnlyBtn  = document.getElementById('viewListOnlyBtn');
var withChartBtn = document.getElementById('viewWithChartBtn');

if (listOnlyBtn) {
  listOnlyBtn.addEventListener('click', function() {
    applyViewMode('list-only');
  });
}

if (withChartBtn) {
  withChartBtn.addEventListener('click', function() {
    applyViewMode('with-chart');
  });
}

// 테이블 위에서 마우스를 누르는 동안에는 리렌더링을 지연 + 동시에 종목 선택까지 처리 (명세서 2-2)
var coinTableBodyEl = document.getElementById('coinTableBody');
if (coinTableBodyEl) {
  coinTableBodyEl.addEventListener('mousedown', function (e) {
    //  별 아이콘 클릭 시에는 종목 선택 무시
    if (e.target.closest('.star-icon')) {
      return;
    }
    
    // 1) 사용자가 테이블을 누르고 있다는 플래그
    isTableMouseDown = true;

    // 2) 실제로 클릭(터치)한 위치에서 가장 가까운 행('.coin-row') 찾기
    var row = e.target.closest('.coin-row');
    if (!row) return;

    var symbol = row.dataset.symbol;
    var exchangeId = row.dataset.exchangeId;
    if (!symbol || !exchangeId) return;

    // 3) 데스크톱/모바일 여부와 상관없이, 이 시점에 곧바로 종목 선택 처리
    //    (우측 차트 열기 or 모바일 모달 열기)
    selectCoin(symbol, exchangeId);
  });
}

// 마우스를 떼는 순간, 지연된 렌더링이 있다면 한 번만 실행
window.addEventListener('mouseup', function() {
  if (!isTableMouseDown) return;
  isTableMouseDown = false;
  
  if (tickerRenderPending) {
    tickerRenderPending = false;
    renderTable();
  }
});

// 모바일 차트 모달 닫기 버튼
var mobileCloseBtn = document.getElementById('mobileChartClose');
if (mobileCloseBtn) {
  mobileCloseBtn.addEventListener('click', closeMobileChart);
}

// 모바일 모달 배경 클릭으로 닫기 (선택사항)
var mobileModal = document.getElementById('mobileChartModal');
if (mobileModal) {
  mobileModal.addEventListener('click', function(e) {
    // 모달 자체(배경)를 클릭한 경우만 닫기
    if (e.target === mobileModal) {
      closeMobileChart();
    }
  });
}

// 뒤로가기 버튼으로 모달 닫기 (모바일 UX)
window.addEventListener('popstate', function(e) {
  var modal = document.getElementById('mobileChartModal');
  if (modal && modal.classList.contains('active')) {
    closeMobileChart();
  }
});

// ---
//  거래소 컬럼 텍스트 잘림 감지 - 아이콘 모드 자동 전환
// - 텍스트가 잘리면(scrollWidth > clientWidth) 아이콘만 표시
// - 공간 충분하면 텍스트 표시 유지
// ---
var exchangeIconModeEnabled = false;

function checkExchangeColumnOverflow() {
  var table = document.querySelector('table');
  if (!table) return;
  
  // 첫 번째 데이터 행의 거래소 셀 확인
  var firstCell = document.querySelector('tr.coin-row td:nth-child(1)');
  if (!firstCell) return;
  
  // 아이콘 모드가 아닐 때만 잘림 체크 (아이콘 모드면 이미 텍스트가 숨겨져서 체크 불가)
  if (!exchangeIconModeEnabled) {
    // 텍스트가 잘리는지 체크 (scrollWidth > clientWidth면 잘림)
    var isOverflowing = firstCell.scrollWidth > firstCell.clientWidth;
    
    if (isOverflowing) {
      // 텍스트 잘림 -> 아이콘 모드 활성화
      table.classList.add('exchange-icon-mode');
      exchangeIconModeEnabled = true;
      console.log(' 아이콘 모드 활성화 (텍스트 잘림 감지)');
    }
  } else {
    // 아이콘 모드일 때: 창이 충분히 넓어졌는지 체크
    // 테이블 너비 기준으로 판단 (600px 이상이면 텍스트 모드로 복귀)
    var tableWidth = table.offsetWidth;
    if (tableWidth >= 600) {
      table.classList.remove('exchange-icon-mode');
      exchangeIconModeEnabled = false;
      console.log(' 텍스트 모드 복귀 (창 너비 충분)');
      
      // 텍스트 모드로 복귀 후 다시 잘림 체크
      setTimeout(function() {
        var recheckCell = document.querySelector('tr.coin-row td:nth-child(1)');
        if (recheckCell && recheckCell.scrollWidth > recheckCell.clientWidth) {
          table.classList.add('exchange-icon-mode');
          exchangeIconModeEnabled = true;
          console.log(' 아이콘 모드 재활성화 (여전히 잘림)');
        }
      }, 50);
    }
  }
}

// 창 크기 변경
window.addEventListener('resize', function() {
  updateMainLayoutHeight();
  
  //  텍스트 잘림 감지
  checkExchangeColumnOverflow();
  
  // 데스크톱으로 전환 시 모바일 모달 닫기
  if (!isMobile()) {
    var modal = document.getElementById('mobileChartModal');
    if (modal && modal.classList.contains('active')) {
      closeMobileChart();
    }
  }
});

// ---
//  Page Visibility API - 탭 전환 대응
// - 탭이 숨겨지면: 렌더링 루프 중지, dirtySet 추가 중단 (CPU 절약)
// - 탭이 열리면: renderTable()로 최신 데이터 동기화 후 루프 재시작
// ---
document.addEventListener('visibilitychange', function() {
  if (document.visibilityState === 'hidden') {
    // 탭이 숨겨짐
    isPageVisible = false;
    console.log(' 탭 숨김 - 렌더링 일시 중지');
    // renderLoopRunning은 renderFrame 내부에서 자동으로 false가 됨
  } else {
    // 탭이 다시 보임
    isPageVisible = true;
    console.log(' 탭 복귀 - 화면 동기화 시작');
    
    // 밀린 깜빡임 효과는 무시하고, 최신 데이터로 테이블 한 번에 렌더링
    dirtySet = {};  // 대기열 비우기
    renderTable();  // 최신 coins 데이터로 전체 렌더링
    
    // 렌더링 루프 재시작
    if (!renderLoopRunning) {
      startRenderLoop();
    }
  }
});

// 초기화
window.addEventListener('load', function() {
  //  푸터 접기/펼치기 초기화
  var footerCollapsible = document.getElementById('footerCollapsible');
  var footerToggleBtn = document.getElementById('footerToggleBtn');
  
  if (footerCollapsible && footerToggleBtn) {
    // localStorage에서 상태 복원
    var savedFooterState = SafeStorage.getItem('footerCollapsed');
    if (savedFooterState === 'true') {
      footerCollapsible.classList.add('collapsed');
      footerToggleBtn.textContent = '▲';
      console.log(' 푸터 상태 복원: 접힘');
    } else {
      footerCollapsible.classList.remove('collapsed');
      footerToggleBtn.textContent = '▼';
      console.log(' 푸터 상태 복원: 펼침');
    }
    
    // 초기화 직후 레이아웃 높이 재계산
    updateMainLayoutHeight();
    
    // 토글 버튼 클릭 이벤트
    footerToggleBtn.addEventListener('click', function() {
      var isCollapsed = footerCollapsible.classList.toggle('collapsed');
      
      // 버튼 아이콘 변경
      footerToggleBtn.textContent = isCollapsed ? '▲' : '▼';
      
      // localStorage에 상태 저장
      SafeStorage.setItem('footerCollapsed', isCollapsed ? 'true' : 'false');
      console.log(' 푸터 상태 변경:', isCollapsed ? '접힘' : '펼침');
      
      // 레이아웃 높이 재계산 (핵심!)
      updateMainLayoutHeight();
    });
  }
  
  //  localStorage에서 필터 설정 복원
  var savedExchanges = SafeStorage.getItem('activeExchanges');
  if (savedExchanges) {
    try {
      var activeExchanges = JSON.parse(savedExchanges);
      console.log(' 저장된 필터 설정 복원:', activeExchanges);
      
      // 모든 체크박스 상태를 복원
      document.querySelectorAll('#exchangeFilterGroup [data-exchange-filter]').forEach(function(label) {
        var exchangeId = label.getAttribute('data-exchange-filter');
        var checkbox = label.querySelector('input[type="checkbox"]');
        if (checkbox && exchangeId) {
          var shouldBeChecked = activeExchanges.includes(exchangeId);
          checkbox.checked = shouldBeChecked;
          if (shouldBeChecked) {
            label.classList.add('active');
          } else {
            label.classList.remove('active');
          }
        }
      });
    } catch (e) {
      console.warn(' 필터 설정 파싱 실패:', e.message);
    }
  } else {
    console.log(' 저장된 필터 설정 없음 - 기본값 사용');
  }
  
  // 모바일에서는 list-only 모드로 시작
  if (isMobile()) {
    applyViewMode('list-only');
  } else {
    applyViewMode('with-chart');
    updateMainLayoutHeight();
  }
  
  //  가상 스크롤: 테이블 wrapper에 scroll 이벤트 리스너 추가
  var tableWrapper = document.querySelector('.coin-table-wrapper');
  if (tableWrapper) {
    tableWrapper.addEventListener('scroll', handleTableScroll, { passive: true });
    console.log(' 가상 스크롤 이벤트 리스너 등록됨');
  }
  
  //  초기 로딩 시 테이블 렌더링 보장
  console.log(' 초기 로딩 - 활성 거래소:', getActiveExchangeIds());
  renderTable();
});

// ---
//  언어 토글 버튼 이벤트 리스너
// ---
document.querySelectorAll('.lang-btn').forEach(function(btn) {
  btn.addEventListener('click', function() {
    var lang = this.getAttribute('data-lang');
    setLanguage(lang);
  });
});

// ---
//  페이지 로드 시 초기화
// ---
// ---
//  쿠키 동의 배너 로직 (글로벌 표준 준수)
// ---
function initCookieBanner() {
  var cookieBanner = document.getElementById('cookieBanner');
  var cookieRejectBtn = document.getElementById('cookieRejectBtn');
  var cookieAllBtn = document.getElementById('cookieAllBtn');
  var cookiePrivacyLink = document.getElementById('cookiePrivacyLink');
  
  // 이미 동의/거부했는지 확인
  var cookieConsent = SafeStorage.getItem('cookieConsent');
  if (cookieConsent) {
    // 이미 선택함 -> 배너 안 보여줌
    return;
  }
  
  // 선택 안 했으면 배너 표시
  cookieBanner.classList.add('show');
  
  // 개인정보처리방침 링크 클릭
  if (cookiePrivacyLink) {
    cookiePrivacyLink.addEventListener('click', function() {
      openLegalModal('privacy');
    });
  }
  
  // [모두 거부] 버튼 - GA4 미실행, 기본 localStorage 기능은 유지
  cookieRejectBtn.addEventListener('click', function() {
    SafeStorage.setItem('cookieConsent', 'reject');
    cookieBanner.classList.remove('show');
    console.log('[Cookie] User rejected analytics cookies');
  });
  
  // [모두 허용] 버튼 - GA4 로드
  cookieAllBtn.addEventListener('click', function() {
    SafeStorage.setItem('cookieConsent', 'all');
    cookieBanner.classList.remove('show');
    loadAnalytics(); // GA4 즉시 로드
    console.log('[Cookie] User accepted all cookies');
  });
}

// 쿠키 배너 다국어 업데이트
function updateCookieBannerLanguage() {
  var cookieBannerText = document.getElementById('cookieBannerText');
  var cookieRejectBtn = document.getElementById('cookieRejectBtn');
  var cookieAllBtn = document.getElementById('cookieAllBtn');
  
  if (cookieBannerText) {
    cookieBannerText.innerHTML = t('cookie.text') + 
      '<a id="cookiePrivacyLink" style="color:#d4af37;text-decoration:underline;cursor:pointer;">' + t('cookie.privacyLink') + '</a>' + 
      t('cookie.textEnd');
    
    // 새로 생성된 링크에 이벤트 리스너 추가
    var newLink = document.getElementById('cookiePrivacyLink');
    if (newLink) {
      newLink.addEventListener('click', function() {
        openLegalModal('privacy');
      });
    }
  }
  if (cookieRejectBtn) {
    cookieRejectBtn.textContent = t('cookie.rejectAll');
  }
  if (cookieAllBtn) {
    cookieAllBtn.textContent = t('cookie.acceptAll');
  }
}

(function initPage() {
  try {
    // 브라우저 언어 자동 감지
    var detectedLang = detectBrowserLanguage();
    setLanguage(detectedLang);
    
    // 쿠키 동의 배너 초기화
    initCookieBanner();
    
    // 채팅 초기화
    initChat();
    
    //  피드백 초기화
    initFeedback();
  } catch (err) {
    console.error('[INIT] 초기화 중 오류 발생 (무시하고 진행):', err);
  }
})();

// WebSocket 연결 시작 (반드시 실행 보장)
connectWebSocket();
</script>
</body>
</html>`);
});

// ---
// HTTP 서버 및 WebSocket 서버
// ---
const http = require('http');

const server = http.createServer(app);

// ---
//  WebSocket 서버 - 압축 전송 활성화
// perMessageDeflate: 텍스트 메시지를 자동 압축하여 대역폭 절감
// ---
const clientWss = new WebSocket.Server({ 
  server,
  perMessageDeflate: {
    zlibDeflateOptions: {
      chunkSize: 1024,
      memLevel: 7,
      level: 3  // 압축 레벨 (1~9, 낮을수록 빠름)
    },
    zlibInflateOptions: {
      chunkSize: 10 * 1024
    },
    clientNoContextTakeover: true,
    serverNoContextTakeover: true,
    serverMaxWindowBits: 10,
    concurrencyLimit: 10,
    threshold: 128  // 128바이트 이상만 압축
  }
});
const clients = new Set();

// ---
//  WebSocket 연결 제한 설정 (DoS 방지)
// ---
const WS_MAX_CONNECTIONS = 10000;       // 동시접속 1만명 (현실적 상한, 서버가 먼저 터짐)
const WS_MAX_PER_IP = 10;               // IP당 최대 접속
const wsConnectionsPerIp = new Map();   // IP별 연결 수 추적

// IP별 연결 수 증가
function incrementIpConnections(ip) {
  const current = wsConnectionsPerIp.get(ip) || 0;
  wsConnectionsPerIp.set(ip, current + 1);
  return current + 1;
}

// IP별 연결 수 감소
function decrementIpConnections(ip) {
  const current = wsConnectionsPerIp.get(ip) || 1;
  if (current <= 1) {
    wsConnectionsPerIp.delete(ip);
  } else {
    wsConnectionsPerIp.set(ip, current - 1);
  }
}

// 연결 허용 여부 확인
function canAcceptConnection(ip) {
  // 전체 연결 수 체크
  if (clients.size >= WS_MAX_CONNECTIONS) {
    console.warn('[WS] 전체 연결 수 한도 초과:', clients.size);
    //  연결 거부 기록
    WsSecurityMonitor.recordConnectionRejection(ip, 'max_connections');
    return { allowed: false, reason: 'max_connections' };
  }
  
  // IP당 연결 수 체크
  const ipConnections = wsConnectionsPerIp.get(ip) || 0;
  if (ipConnections >= WS_MAX_PER_IP) {
    console.warn('[WS] IP당 연결 수 한도 초과:', ip.slice(-8), ipConnections);
    //  연결 거부 기록
    WsSecurityMonitor.recordConnectionRejection(ip, 'max_per_ip');
    return { allowed: false, reason: 'max_per_ip' };
  }
  
  return { allowed: true };
}

// ---
//  WebSocket 메시지 Rate Limit 설정 (도배 방지)
// ---
const WS_MESSAGE_INTERVAL = 1000;       // 메시지 최소 간격 (1초)
const WS_RATE_LIMIT_WARNINGS = 3;       // 경고 횟수 (초과 시 연결 종료)

// Rate Limit 체크 함수
function checkWsRateLimit(ws) {
  const now = Date.now();
  
  // 초기화
  if (!ws.lastMessageTime) {
    ws.lastMessageTime = 0;
    ws.rateLimitWarnings = 0;
  }
  
  const elapsed = now - ws.lastMessageTime;
  
  if (elapsed < WS_MESSAGE_INTERVAL) {
    ws.rateLimitWarnings++;
    
    //  Rate Limit 위반 기록
    WsSecurityMonitor.recordRateLimitViolation(ws.clientIp, ws.chatClientId);
    
    if (ws.rateLimitWarnings >= WS_RATE_LIMIT_WARNINGS) {
      console.warn('[WS] Rate Limit 반복 위반으로 연결 종료:', ws.chatClientId);
      ws.send(JSON.stringify({
        type: 'system',
        text: 'Too many messages. Connection terminated. / 메시지가 너무 빠릅니다. 연결이 종료됩니다.'
      }));
      ws.terminate();
      return false;
    }
    
    ws.send(JSON.stringify({
      type: 'system',
      text: 'Please wait 1 second between messages. / 메시지는 1초에 한 번만 보낼 수 있습니다. (' + ws.rateLimitWarnings + '/' + WS_RATE_LIMIT_WARNINGS + ')'
    }));
    return false;
  }
  
  ws.lastMessageTime = now;
  ws.rateLimitWarnings = 0;  // 정상 메시지 시 경고 카운터 리셋
  return true;
}

// ---
//  순위표 스트리밍 (Ranking List Streaming) + Diffing
// - 5초마다 정렬된 심볼 리스트 전송
// - 이전 순서와 동일하면 전송 스킵 (불필요한 트래픽 제거)
// - 데이터 사용량 극적 감소
// ---
const RANKING_UPDATE_INTERVAL = 5000;  // 5초마다 순위표 확인

// ════════════════════════════════════════════════════════════════
//  순위표 브로드캐스트 (5초마다) - 타임프레임별 맞춤 전송!
// ════════════════════════════════════════════════════════════════
// [Bug Fix] 기존 문제점:
//   - coinData.upProbability는 서버 기본 타임프레임(1분 또는 240분) 값
//   - 모든 클라이언트에게 동일한 순위표 전송 → 타임프레임 불일치!
//   - 30분봉 보는 사용자에게 1분봉 기준 순위표가 전송됨
//   - 결과: 순위가 섞이는 "Rank Jumping" 버그
//  broadcastCoinData() 호출로 교체
//   - 각 클라이언트의 타임프레임에 맞는 순위표 전송
//   - sendCoinDataToClient(ws, timeframe)이 해당 TF 캐시에서 값 조회
// ════════════════════════════════════════════════════════════════
setInterval(() => {
  if (clients.size === 0) return;
  
  //  타임프레임별 맞춤 순위표 전송
  // - broadcastCoinData()는 clientsByTimeframe으로 그룹화 후
  // - 각 그룹에 sendCoinDataToClient(ws, timeframe) 호출
  broadcastCoinData();
  
}, RANKING_UPDATE_INTERVAL);

// ---
//  채팅 로그 파일 저장/로드
//  chatMessageIdCounter 추가 - 메시지 고유 ID 관리
// ---
const CHAT_LOG_FILE = path.join(DATA_DIR, 'chat_log.json');
const CHAT_LOAD_LIMIT = 300;  // 신규 접속자에게 보여줄 최대 메시지 수
let chatHistory = [];
let chatMessageIdCounter = 0;  //  채팅 메시지 ID 카운터

// ---
//  금지어 필터 (욕설, 광고, 스팸)
// ---
const BANNED_WORDS = [
  // 한국어 욕설
  '시발', '씨발', '씨팔', '시팔', '씹', '병신', '빙신', '지랄', '좆', '존나', '졸라',
  '개새끼', '개색끼', '새끼', '색끼', '미친놈', '미친년', '느금마', '니애미', '니엄마',
  '꺼져', '닥쳐', '죽어', '뒤져', '꺼지', '닥쳐라',
  // 영어 욕설
  'fuck', 'shit', 'damn', 'bitch', 'asshole', 'bastard', 'dick', 'cock', 'pussy',
  'cunt', 'whore', 'slut', 'nigger', 'nigga', 'faggot', 'retard',
  // 스팸/광고 키워드
  '텔레그램', 'telegram', 'kakao', '카카오톡', '카톡', 'whatsapp', '왓츠앱',
  '무료상담', '수익보장', '100%수익', '원금보장', '투자상담', '코인추천',
  '선물거래', '레버리지', 'vip', 'VIP', '단톡방', '오픈채팅',
  // 사기/피싱 관련
  'airdrop', '에어드랍', 'giveaway', '이벤트당첨', '당첨자', '클릭하세요'
];

// URL 패턴 (광고 링크 차단)
const URL_PATTERN = /https?:\/\/|www\.|\.com|\.net|\.org|\.io|\.kr|\.co|bit\.ly|t\.me/i;

// 금지어 검사 함수
function containsBannedContent(text) {
  const lowerText = text.toLowerCase();
  
  // 금지어 검사
  for (const word of BANNED_WORDS) {
    if (lowerText.includes(word.toLowerCase())) {
      return { blocked: true, reason: 'banned_word', word: word };
    }
  }
  
  // URL 검사
  if (URL_PATTERN.test(text)) {
    return { blocked: true, reason: 'url' };
  }
  
  return { blocked: false };
}

// 채팅 로그 파일에서 복원 (영구 저장, 제한 없음)
//  id 없는 메시지에 id 부여, chatMessageIdCounter 초기화
function loadChatHistory() {
  try {
    if (!fs.existsSync(CHAT_LOG_FILE)) {
      console.log('[CHAT] [Chat] 채팅 로그 파일 없음 → 빈 히스토리로 시작');
      return;
    }
    
    const data = fs.readFileSync(CHAT_LOG_FILE, 'utf8');
    const parsed = JSON.parse(data);
    
    if (Array.isArray(parsed)) {
      //  기존 메시지에 id가 없으면 순서대로 부여
      let maxId = 0;
      let needsSave = false;
      
      chatHistory = parsed.map((msg, index) => {
        if (typeof msg.id !== 'number') {
          msg.id = index + 1;
          needsSave = true;
        }
        if (msg.id > maxId) {
          maxId = msg.id;
        }
        return msg;
      });
      
      // chatMessageIdCounter를 최대 id로 초기화
      chatMessageIdCounter = maxId;
      
      // id가 부여된 경우 파일 다시 저장
      if (needsSave) {
        saveChatHistory();
        console.log('[CHAT] [Chat] 채팅 로그에 id 부여 완료');
      }
      
      console.log('[CHAT] [Chat] 채팅 로그 복원 완료: ' + chatHistory.length + '개 메시지 (maxId: ' + chatMessageIdCounter + ')');
    }
  } catch (error) {
    console.error('[ERROR] [Chat] 채팅 로그 로드 실패:', error.message);
    chatHistory = [];
  }
}

// 채팅 로그 파일에 저장 (영구 저장, 제한 없음)
function saveChatHistory() {
  try {
    fs.writeFileSync(CHAT_LOG_FILE, JSON.stringify(chatHistory, null, 2), 'utf8');
  } catch (error) {
    console.error('[ERROR] [Chat] 채팅 로그 저장 실패:', error.message);
  }
}

// 채팅 메시지 추가 (영구 저장)
//  id 부여 로직 추가
function addChatToHistory(msg) {
  const timestampedMsg = {
    id: (++chatMessageIdCounter),  //  고유 ID 부여
    ...msg,
    timestamp: Date.now()  // Unix timestamp (ms) - 클라이언트에서 현지 시간으로 변환
  };
  chatHistory.push(timestampedMsg);
  
  // 영구 저장 (제한 없음)
  saveChatHistory();
  
  return timestampedMsg;  // id, timestamp 포함된 메시지 반환
}

// 신규 접속자에게 보낼 히스토리 (최근 300개, deleted 처리)
//  deleted 메시지는 noTrace 여부에 따라 처리
//   - noTrace=true: 완전히 제외 (흔적 없음)
//   - noTrace=false: stubText로 대체하여 표시
function getChatHistoryForClient() {
  return chatHistory
    .filter(msg => {
      if (!msg.deleted) return true;  // 삭제 안 된 메시지는 포함
      if (msg.noTrace) return false;  // 흔적 없이 삭제된 메시지는 제외
      return true;  // 흔적 있는 삭제 메시지는 포함 (stubText로 표시)
    })
    .map(msg => {
      if (msg.deleted && !msg.noTrace) {
        // 삭제된 메시지는 stubText만 전송 (원본 내용 숨김)
        return {
          id: msg.id,
          type: 'chat',
          timestamp: msg.timestamp,
          deleted: true,
          stubText: msg.stubText,
          deletedBy: msg.deletedBy
        };
      }
      return msg;
    })
    .slice(-CHAT_LOAD_LIMIT);
}

//  ID로 채팅 메시지 찾기
function findChatMessageById(id) {
  return chatHistory.find(msg => msg.id === id);
}

//  채팅 Moderation 처리 함수
function handleChatModeration(ws, msg) {
  const { action, messageId, noTrace } = msg;
  
  if (!messageId) return;
  
  const entry = findChatMessageById(Number(messageId));
  if (!entry) {
    console.log('[Moderation] 메시지 없음:', messageId);
    return;
  }
  
  // (1) 자기 메시지 삭제: self_delete
  if (action === 'self_delete') {
    // 본인 메시지인지 확인 (clientId 또는 ipTag로)
    const isOwner = (entry.clientId && ws.chatClientId && entry.clientId === ws.chatClientId) ||
                    (entry.ipTag && ws.chatIpTag && entry.ipTag === ws.chatIpTag);
    
    if (!isOwner) {
      console.log('[Moderation] 삭제 거부 (권한없음):', messageId, 'requester:', ws.chatClientId);
      return;
    }
    
    entry.deleted = true;
    entry.deletedBy = 'self';
    entry.deletedAt = Date.now();
    entry.stubText = '작성자가 메시지를 삭제했습니다.';
    entry.noTrace = false;
    saveChatHistory();
    
    console.log('[Moderation] 자기 삭제:', messageId, 'by', ws.chatClientId);
    
    // 모든 클라이언트에게 업데이트 알림
    const updateMsg = JSON.stringify({
      type: 'chat_update',
      id: entry.id,
      stubText: entry.stubText,
      deletedBy: 'self'
    });
    clients.forEach(c => {
      if (c.readyState === WebSocket.OPEN) {
        c.send(updateMsg);
      }
    });
    return;
  }
  
  // (2) 관리자 숨기기: admin_hide
  if (action === 'admin_hide') {
    if (!ws.isAdmin) {
      console.log('[Moderation] 관리자 아님 (admin_hide 거부):', ws.chatClientId);
      return;
    }
    
    entry.deleted = true;
    entry.deletedBy = 'admin';
    entry.deletedAt = Date.now();
    entry.stubText = '관리자가 이 메시지의 표시를 중단했습니다.';
    entry.noTrace = false;
    saveChatHistory();
    
    console.log('[Admin] 메시지 숨김:', messageId);
    
    // 모든 클라이언트에게 업데이트 알림
    const updateMsg = JSON.stringify({
      type: 'chat_update',
      id: entry.id,
      stubText: entry.stubText,
      deletedBy: 'admin'
    });
    clients.forEach(c => {
      if (c.readyState === WebSocket.OPEN) {
        c.send(updateMsg);
      }
    });
    return;
  }
  
  // (3) 관리자 삭제: admin_delete
  if (action === 'admin_delete') {
    if (!ws.isAdmin) {
      console.log('[Moderation] 관리자 아님 (admin_delete 거부):', ws.chatClientId);
      return;
    }
    
    entry.deleted = true;
    entry.deletedBy = 'admin';
    entry.deletedAt = Date.now();
    entry.noTrace = !!noTrace;
    
    if (entry.noTrace) {
      // 흔적 없이 삭제 - DOM에서 완전 제거
      saveChatHistory();
      console.log('[Admin] 메시지 삭제 (흔적 없이):', messageId);
      
      const removeMsg = JSON.stringify({
        type: 'chat_remove',
        messageId: entry.id
      });
      clients.forEach(c => {
        if (c.readyState === WebSocket.OPEN) {
          c.send(removeMsg);
        }
      });
    } else {
      // 흔적 남기기 - stubText로 대체
      entry.stubText = '관리자가 이 메시지의 표시를 중단했습니다.';
      saveChatHistory();
      console.log('[Admin] 메시지 삭제 (흔적 남김):', messageId);
      
      const updateMsg = JSON.stringify({
        type: 'chat_update',
        id: entry.id,
        stubText: entry.stubText,
        deletedBy: 'admin'
      });
      clients.forEach(c => {
        if (c.readyState === WebSocket.OPEN) {
          c.send(updateMsg);
        }
      });
    }
    return;
  }
}

// 서버 시작 시 채팅 로그 로드
loadChatHistory();

// ---
//  채팅 브로드캐스트 헬퍼 함수
// ---
function broadcastChatMessage(msg) {
  // 히스토리에 추가 (timestamp 포함된 메시지 반환)
  const timestampedMsg = addChatToHistory(msg);
  
  // timestamp 포함하여 브로드캐스트
  const message = JSON.stringify(timestampedMsg);
  clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(message);
    }
  });
}

//  접속자 수 브로드캐스트 (UI 숨김 처리됨)
function broadcastUserCount() {
  const count = clients.size;
  const message = JSON.stringify({ type: 'count', count: count });
  clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(message);
    }
  });
}

clientWss.on('connection', (ws, req) => {
  //  Reverse Proxy 대응 IP 추출 (x-forwarded-for 우선)
  const ip = getClientIp(req);
  
  //  연결 제한 체크
  const connectionCheck = canAcceptConnection(ip);
  if (!connectionCheck.allowed) {
    console.warn('[WS] 연결 거부:', connectionCheck.reason, 'IP:', ip.slice(-8));
    ws.close(1013, connectionCheck.reason);  // 1013 = Try Again Later
    return;
  }
  
  //  IP 연결 수 증가
  incrementIpConnections(ip);
  
  //  연결 기록 (보안 모니터링)
  WsSecurityMonitor.recordConnection(ip);
  
  console.log('[OK] 클라이언트 WebSocket 연결됨 (IP:', ip.slice(-8), ', 총:', clients.size + 1, ')');
  
  //  발신자 식별자 생성
  ws.chatClientId = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  
  //  CHAT_SALT를 사용한 IP 해싱 (보안 강화)
  ws.chatIpTag = ip && ip !== 'unknown'
    ? crypto.createHash('sha256').update(ip + CHAT_SALT).digest('hex').slice(0, 16)
    : null;
  
  //  ws 객체에 IP 저장 (연결 종료 시 사용)
  ws.clientIp = ip;
  
  //  클라이언트별 visibleSymbols Set 초기화
  ws.visibleSymbols = new Set();  // 현재 보고 있는 심볼들
  ws.visibleExchanges = new Set();  // 심볼+거래소 조합 ('UPBIT_SPOT:BTC')
  
  // ════════════════════════════════════════════════════════════════
  //  클라이언트별 타임프레임 초기화
  // - 각 클라이언트가 독립적인 타임프레임을 가짐
  // - 서버 기본값(DEFAULT_TIMEFRAME)으로 시작
  //  subscribeToTimeframe 헬퍼 함수 사용
  // ════════════════════════════════════════════════════════════════
  subscribeToTimeframe(ws, DEFAULT_TIMEFRAME);
  
  clients.add(ws);
  
  //  접속자 수 브로드캐스트 (연결 시)
  broadcastUserCount();
  
  //  subscribe 메시지 처리 +  채팅 메시지 처리
  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString());
      
      // ════════════════════════════════════════════════════════════════
      //  타임프레임 변경 요청 처리 (잔상 버그 수정!)
      // 1. 무조건 즉시 전송 (캐시 있으면 숫자, 없으면 Calc...)
      // 2. 캐시 없으면 백그라운드 백필 → 완료 후 재전송
      //  Request ID 저장 - stale response 필터링 지원
      // ════════════════════════════════════════════════════════════════
      if (msg.type === 'setTimeframe' && typeof msg.timeframe === 'number') {
        const tf = msg.timeframe;
        const requestId = msg.requestId;  //  클라이언트가 보낸 요청 ID
        
        if (ALLOWED_TIMEFRAMES.includes(tf)) {
          //  subscribeToTimeframe 헬퍼 함수 사용
          subscribeToTimeframe(ws, tf);
          ws.lastRequestId = requestId;  //  요청 ID 저장
          console.log('[WS]  타임프레임 변경: ' + tf + '분, requestId=' + requestId);
          
          // ════════════════════════════════════════════════════════════════
          //  그냥 전송하고 끝! JIT 백필 없음!
          // - 캐시 있으면 숫자 표시
          // - 캐시 없으면 "Calc..." 표시
          // - 서버가 Phase 2에서 해당 TF 완료하면 자동으로 푸시됨
          // ════════════════════════════════════════════════════════════════
          sendCoinDataToClient(ws, tf);
        }
        return;
      }
      
      if (msg.type === 'subscribe' && Array.isArray(msg.visibleSymbols)) {
        // 클라이언트가 보고 있는 심볼 목록 업데이트
        ws.visibleSymbols = new Set(msg.visibleSymbols);
        
        // exchange:symbol 형태로도 저장 (더 정밀한 매칭용)
        if (Array.isArray(msg.visibleKeys)) {
          ws.visibleExchanges = new Set(msg.visibleKeys);
        }
        
        // console.log(' 구독 업데이트:', ws.visibleSymbols.size, '개 심볼');
      }
      
      // ---
      //  채팅 메시지 처리
      // - 일반 채팅: 모든 클라이언트에게 브로드캐스트
      // - 관리자 공지: 특정 명령어로 시작하면 공지로 변환
      //  서버측 Rate Limit 추가
      // ---
      if (msg.type === 'chat' && msg.text && msg.nick) {
        //  서버측 Rate Limit 체크
        if (!checkWsRateLimit(ws)) {
          return;  // Rate Limit 초과 시 처리 중단
        }
        
        const text = String(msg.text).trim();
        const nick = String(msg.nick).trim().slice(0, 20);  // 닉네임 최대 20자
        
        // 빈 메시지 무시
        if (!text || text.length === 0) return;
        
        // 메시지 길이 제한 (200자)
        const safeText = escapeHtml(text.slice(0, 200));  //  XSS 방지
        
        //  관리자 명령어 (환경변수에서 로드)
        // - 기존 난독화 방식 제거, 환경변수 기반으로 변경
        // - ADMIN_CHAT_CMD는 파일 상단에서 loadSecurityEnv()로 로드됨
        const adminPrefix = '/' + ADMIN_CHAT_CMD + ' ';
        const adminExact = '/' + ADMIN_CHAT_CMD;
        
        //  관리자 모드 활성화 (정확히 일치할 때)
        if (text === adminExact) {
          ws.isAdmin = true;
          ws.send(JSON.stringify({
            type: 'system',
            text: '관리자 모드가 활성화되었습니다.',
            adminMode: true  // 프론트에서 chatAdminMode = true 설정용
          }));
          console.log('[ADMIN] 관리자 모드 활성화:', ws.chatClientId);
          return;  // 채팅으로 표시하지 않음
        }
        
        if (text.startsWith(adminPrefix)) {
          // 관리자 공지 메시지 (금지어 필터 우회)
          const noticeText = text.slice(adminPrefix.length).trim();
          if (noticeText.length > 0) {
            broadcastChatMessage({
              type: 'admin',
              nick: '공지',
              text: escapeHtml(noticeText)  //  XSS 방지
            });
            console.log('[ADMIN] 공지 전송:', noticeText.slice(0, 50) + '...');
          }
        } else {
          // 금지어 필터 검사
          const filterResult = containsBannedContent(safeText);
          
          if (filterResult.blocked) {
            // 금지어 감지 → 해당 사용자에게만 경고 메시지 전송
            const warningMsg = filterResult.reason === 'url' 
              ? { type: 'system', text: 'Links are not allowed in chat. / 채팅에 링크를 포함할 수 없습니다.' }
              : { type: 'system', text: 'Your message contains inappropriate content. / 부적절한 내용이 포함되어 있습니다.' };
            
            ws.send(JSON.stringify(warningMsg));
            console.log('[CHAT] 금지어 차단:', nick, '→', filterResult.reason, filterResult.word || '');
          } else {
            // 일반 채팅 메시지
            //  clientId, ipTag 추가
            broadcastChatMessage({
              type: 'chat',
              nick: nick,
              text: safeText,
              clientId: ws.chatClientId,
              ipTag: ws.chatIpTag
            });
          }
        }
      }
      
      // ---
      //  채팅 Moderation 처리
      // - self_delete: 본인 메시지 삭제
      // - admin_hide: 관리자 숨김
      // - admin_delete: 관리자 삭제 (흔적 유무 선택)
      // ---
      if (msg.type === 'chat_moderation') {
        handleChatModeration(ws, msg);
      }
    } catch (e) {
      // JSON 파싱 오류 무시
    }
  });
  
  ws.on('close', () => {
    console.log('[INFO] 클라이언트 WebSocket 연결 종료 (IP:', (ws.clientIp || '').slice(-8), ')');
    clients.delete(ws);
    
    //  구독 해제 (subscriptions + clientTimeframes 모두 정리)
    unsubscribeClient(ws);
    
    //  IP 연결 수 감소
    if (ws.clientIp) {
      decrementIpConnections(ws.clientIp);
      //  연결 해제 기록 (보안 모니터링)
      WsSecurityMonitor.recordDisconnection(ws.clientIp);
    }
    //  접속자 수 브로드캐스트 (해제 시)
    broadcastUserCount();
  });
  
  ws.on('error', (error) => {
    console.error('WebSocket 에러:', error.message);
    clients.delete(ws);
    
    //  에러 시에도 구독 해제
    unsubscribeClient(ws);
    
    //  IP 연결 수 감소
    if (ws.clientIp) {
      decrementIpConnections(ws.clientIp);
      //  에러로 인한 연결 해제도 기록
      WsSecurityMonitor.recordDisconnection(ws.clientIp);
    }
    broadcastUserCount();
  });
  
  // ════════════════════════════════════════════════════════════════
  //  초기 데이터도 클라이언트 타임프레임에 맞춰 전송
  // - ws.clientTimeframe (초기값 = DEFAULT_TIMEFRAME)에 해당하는 모멘텀 조회
  // - momentumCacheMap에서 해당 타임프레임 데이터 사용
  // ════════════════════════════════════════════════════════════════
  const initialTf = ws.clientTimeframe || DEFAULT_TIMEFRAME || 240;
  const upbitCache = momentumCacheMap.upbit[initialTf];
  const bithumbCache = momentumCacheMap.bithumb[initialTf];
  
  const compactInitial = coinData.map(c => {
    let upVal = 'CALC';
    let downVal = 'CALC';
    
    // 거래소별 다차원 캐시에서 해당 타임프레임 모멘텀 조회
    if (c.exchange === 'UPBIT_SPOT') {
      const m = upbitCache?.get(c.symbol);
      if (m) {
        upVal = m.up === undefined ? 'CALC' : (m.up === null ? '-' : m.up);
        downVal = m.down === undefined ? 'CALC' : (m.down === null ? '-' : m.down);
      }
    } else if (c.exchange === 'BITHUMB_SPOT') {
      const m = bithumbCache?.get(c.symbol);
      if (m) {
        upVal = m.up === undefined ? 'CALC' : (m.up === null ? '-' : m.up);
        downVal = m.down === undefined ? 'CALC' : (m.down === null ? '-' : m.down);
      }
    } else {
      // 글로벌 거래소: globalMomentumCache에서 조회
      const globalKey = c.exchange + ':' + c.symbol;
      const m = globalMomentumCache[initialTf]?.get(globalKey);
      if (m) {
        upVal = m.up === undefined ? 'CALC' : (m.up === null ? '-' : m.up);
        downVal = m.down === undefined ? 'CALC' : (m.down === null ? '-' : m.down);
      }
    }
    
    return [c.exchange, c.symbol, c.price, upVal, downVal, c.change24h];
  });
  
  //  initial 메시지에 환율 정보 포함
  //  채팅 히스토리도 함께 전송
  //  clientId 추가
  ws.send(JSON.stringify({
    type: 'initial',
    data: compactInitial,
    usdtKrwRate: ExchangeRateManager.getRate(),  // 현재 환율 (1 USDT = ? KRW)
    chatHistory: getChatHistoryForClient(),  // 최근 300개만 전송
    clientId: ws.chatClientId  //  클라이언트 식별자
  }));
});

// ---
// 서버 시작
// ---
server.listen(PORT, async () => {
  console.log('[START] 서버 시작!');
  console.log('[WEB] http://localhost:' + PORT);
  
  // ---
  // [보안] WebSocket 보안 모니터링 시작
  // ---
  WsSecurityMonitor.start();
  
  // ---
  // [보안] npm audit 실행 (취약점 검사)
  // ---
  checkNpmAudit();
  
  // ---
  // [문제 1 해결] 스냅샷 로드 (가장 먼저! - 즉시 % 수치 표시)
  // ---
  console.log('[SNAP] [최우선] coinData 스냅샷 로드 시도...');
  const snapshotLoaded = loadCoinDataSnapshot();
  if (snapshotLoaded) {
    console.log('[OK] 스냅샷에서 ' + coinData.length + '개 코인 즉시 복원됨! (50% 표시 방지)');
  }
  
  // ---
  // 0단계: 다차원 모멘텀 캐시 초기화 (명세 2)
  // ---
  console.log('[CACHE] [0단계] 다차원 모멘텀 캐시 초기화...');
  initMomentumCacheMap();
  
  // ---
  // 1단계: 캐시 파일 복원 (즉시 데이터 제공을 위해 가장 먼저!)
  //  모멘텀 캐시 파일 복원 추가
  // ---
  console.log('[DIR] [1단계] 캐시 파일 복원 시작...');
  
  // 빗썸 캔들 캐시 파일 복원
  loadCandleCacheFromFile();
  
  //  빗썸 1시간봉 캐시 파일 복원 (4시간봉 합성용)
  load1HourCacheFromFile();
  
  // 업비트 24시간 전 가격 캐시 파일 복원 (수정 1)
  loadUpbitPriceCacheFromFile();
  
  // 업비트 캔들 캐시 파일 복원 (수정 2)
  loadUpbitCandleCacheFromFile();
  
  //  모멘텀 캐시 파일 복원 (새로 추가!)
  const momentumCacheLoaded = loadMomentumCacheFromFile();
  if (momentumCacheLoaded) {
    console.log('[OK]  모멘텀 캐시에서 즉시 복원됨! (API 호출 없이 모든 타임프레임 데이터 사용 가능)');
  }
  
  // ---
  // 2단계: 동적 마켓 코드 조회 (명세 1: 하드코딩 제거)
  // ---
  console.log('[SCAN] [2단계] 동적 마켓 코드 조회...');
  await fetchMarketCodes();
  
  // ---
  // 2.5단계:  환율 관리자 초기화 (즉시 완료!)
  // - 파일 캐시에서 즉시 로드 (블로킹 없음)
  // - API 호출은 백그라운드에서 비동기 실행
  // ---
  console.log('[RATE] [2.5단계] 환율 관리자 초기화 (파일 캐시 우선)...');
  ExchangeRateManager.initialize();  //  await 제거 - 즉시 반환
  console.log('[OK] 환율 관리자 초기화 완료! (현재 환율: 1 USDT = ' + ExchangeRateManager.getRate().toLocaleString() + ' KRW)');
  
  // ---
  // 3단계: 모멘텀 즉시 복원 및 빗썸 즉시 재계산 (대기 시간 0초!)
  //  캐시 파일에서 복원 → coinData 반영 → 빗썸 즉시 재계산
  // ---
  console.log('[FAST] [3단계] 모멘텀 즉시 복원 및 빗썸 즉시 재계산...');
  
  // 3-1. 모멘텀 캐시 파일에서 복원된 데이터를 coinData에 반영
  if (momentumCacheLoaded) {
    console.log('   [DATA] [3-1] 모멘텀 캐시 → coinData 반영 중...');
    let appliedCount = 0;
    
    coinData.forEach(coin => {
      const tf = momentumTimeframe;
      
      if (coin.exchange === 'UPBIT_SPOT' && momentumCacheMap.upbit[tf]) {
        const momentum = momentumCacheMap.upbit[tf].get(coin.symbol);
        if (momentum) {
          coin.upProbability = momentum.up;
          coin.downProbability = momentum.down;
          appliedCount++;
        }
      } else if (coin.exchange === 'BITHUMB_SPOT' && momentumCacheMap.bithumb[tf]) {
        const momentum = momentumCacheMap.bithumb[tf].get(coin.symbol);
        if (momentum) {
          coin.upProbability = momentum.up;
          coin.downProbability = momentum.down;
          appliedCount++;
        }
      } else {
        // ════════════════════════════════════════════════════════════════
        //  글로벌 거래소도 캐시 복원! (국내와 동일한 대우)
        // - BINANCE_SPOT, BINANCE_FUTURES, OKX_SPOT, OKX_FUTURES
        // - globalMomentumCache[tf]에서 "EXCHANGE:SYMBOL" 키로 조회
        // ════════════════════════════════════════════════════════════════
        const globalKey = coin.exchange + ':' + coin.symbol;
        const momentum = globalMomentumCache[tf]?.get(globalKey);
        if (momentum) {
          coin.upProbability = momentum.up;
          coin.downProbability = momentum.down;
          appliedCount++;
        }
      }
    });
    
    console.log('   [OK] [3-1] 모멘텀 캐시 → coinData 반영 완료! (' + appliedCount + '개 코인)');
  }
  
  // 3-2. 빗썸 캔들 캐시에서 모멘텀 즉시 재계산 (0.1초 이내)
  //  최소 표본 수(359) 검사 추가
  console.log('   [FAST] [3-2] 빗썸 모멘텀 즉시 재계산 (캔들 캐시 기반)...');
  let bithumbRecalcCount = 0;
  
  bithumbCandleCache.forEach((candles, symbol) => {
    if (candles && candles.length >= 2) {
      const completedCandles = candles.slice(0, -1);
      if (completedCandles.length >= 2) {
        //  360개 캔들 기준으로 계산
        const useCandles = completedCandles.slice(-Math.min(MOMENTUM_CANDLE_COUNT, completedCandles.length));
        const n = useCandles.length - 1;
        
        //  최소 표본 수 검사 - 미달 시 null
        if (n < MIN_CANDLES_FOR_MOMENTUM - 1) {
          const momentum = { up: null, down: null };
          bithumbMomentumCache.set(symbol, momentum);
          
          if (!momentumCacheMap.bithumb[momentumTimeframe]) {
            momentumCacheMap.bithumb[momentumTimeframe] = new Map();
          }
          momentumCacheMap.bithumb[momentumTimeframe].set(symbol, momentum);
          
          coinData.forEach(coin => {
            if (coin.symbol === symbol && coin.exchange === 'BITHUMB_SPOT') {
              coin.upProbability = null;
              coin.downProbability = null;
            }
          });
          return;  // 다음 심볼로
        }
        
        let highBreaks = 0, lowBreaks = 0;
        
        for (let i = useCandles.length - 1; i > 0; i--) {
          if (useCandles[i].high > useCandles[i - 1].high) highBreaks++;
          if (useCandles[i].low < useCandles[i - 1].low) lowBreaks++;
        }
        
        const momentum = { 
          up: Math.round((highBreaks / n) * 100), 
          down: Math.round((lowBreaks / n) * 100) 
        };
        
        bithumbMomentumCache.set(symbol, momentum);
        
        // 다차원 캐시에도 저장
        if (!momentumCacheMap.bithumb[momentumTimeframe]) {
          momentumCacheMap.bithumb[momentumTimeframe] = new Map();
        }
        momentumCacheMap.bithumb[momentumTimeframe].set(symbol, momentum);
        
        // coinData에도 반영
        coinData.forEach(coin => {
          if (coin.symbol === symbol && coin.exchange === 'BITHUMB_SPOT') {
            coin.upProbability = momentum.up;
            coin.downProbability = momentum.down;
          }
        });
        bithumbRecalcCount++;
      }
    }
  });
  
  console.log('   [OK] [3-2] 빗썸 모멘텀 즉시 재계산 완료! (' + bithumbRecalcCount + '개 코인)');
  
  // 3-3. 기존 캔들 캐시에서 모멘텀 계산 (업비트 포함)
  console.log('   [FAST] [3-3] 업비트 모멘텀 즉시 계산 (캔들 캐시 기반)...');
  calculateAllMomentumFromCacheSync();
  
  console.log('[OK] [3단계] 모멘텀 즉시 복원 완료! (API 호출 없이 데이터 사용 가능)');
  
  // ---
  // 3.5단계:  글로벌 캔들 파일 복원 (스마트 초기화)
  // - 서버 재시작 시 과거 데이터 즉시 로드
  // - 파일 없거나 만료된 경우 Backfill로 보충
  // ---
  console.log('[DIR] [3.5단계] 글로벌 캔들 파일 복원 (스마트 초기화)...');
  const globalLoadResult = loadGlobalCandleStoreFromFile();
  
  if (globalLoadResult.loaded && globalLoadResult.symbols > 0) {
    console.log('   [OK] 글로벌 캔들 ' + globalLoadResult.symbols + '개 심볼 로드됨');
    
    //  파일에서 로드한 데이터로 즉시 모멘텀 계산
    console.log('   [FAST] [3.5-1] 글로벌 거래소 모멘텀 즉시 계산...');
    updateGlobalMomentumCaches();
    
    //  계산된 모멘텀을 coinData에 즉시 반영
    console.log('   [FAST] [3.5-2] 글로벌 모멘텀 → coinData 즉시 반영...');
    applyGlobalMomentumToCoinData();
    
    console.log('   [OK] 글로벌 모멘텀 즉시 계산 및 반영 완료!');
  }
  
  // 더미 데이터 (테스트용) - 논리 ID 체계 사용
  console.log('[TEST] 더미 데이터 추가 (테스트용)');
  coinData.push({
    exchange: 'UPBIT_SPOT',
    symbol: 'BTC',
    price: 144500000,
    upProbability: 50,
    downProbability: 50,
    change24h: 0,
    lastUpdate: new Date(),
    isDummy: true
  });
  
  // ---
  // 4단계: WebSocket 연결 (실시간 데이터 수신)
  //  Backfill보다 먼저 실행하여 즉시 틱 수신
  // ---
  console.log('[CONN] [4단계] WebSocket 연결 시작...');
  connectUpbit();
  connectBithumb();
  
  //  글로벌 거래소 WebSocket 연결 (바이낸스, OKX)
  console.log('[WEB] [4단계-글로벌] 글로벌 거래소 WebSocket 연결 시작...');
  connectBinanceSpot();
  connectBinanceFutures();
  connectOkxSpot();
  connectOkxFutures();
  
  // ---
  // 4.5단계:  글로벌 거래소 스마트 Backfill (비동기)
  // - await 없이 백그라운드 실행 (Non-blocking)
  // - 기존 파일 데이터와 병합하여 공백 메우기
  // - 완료 후 모멘텀 재계산 + 파일 저장
  // ---
  console.log('[SYNC] [4.5단계] 글로벌 거래소 스마트 Backfill 시작 (백그라운드)...');
  backfillGlobalCandles().then(backfillResult => {
    if (backfillResult.success > 0) {
      console.log('[OK] [Background] 글로벌 스마트 Backfill 완료!');
      console.log('   [DATA] 성공: ' + backfillResult.success + '개 심볼');
      console.log('   [SYNC] 병합: ' + (backfillResult.merged || 0) + '개 심볼');
      
      // Backfill 완료 후 모멘텀 재계산
      updateGlobalMomentumCaches();
      
      // coinData에도 글로벌 모멘텀 반영
      applyGlobalMomentumToCoinData();
      
      //  4.5단계 완료 후에도 브로드캐스트!
      broadcastCoinData('R');
      console.log('[BROADCAST]  4.5단계 완료 → 전체 클라이언트에 브로드캐스트!');
    }
  }).catch(err => {
    console.error('[ERROR] [Background] 글로벌 Backfill 오류:', err.message);
  });
  
  // ---
  //  4.6단계: 신선도 기반 즉시 표시 + 우선순위 증분 수집
  // ════════════════════════════════════════════════════════════════
  // Phase A: 캐시 복원 → 신선도 분석 → 신선한 것 즉시 브로드캐스트
  // Phase B: 노후 데이터 증분 필요량 정렬 → 적게 필요한 것부터 수집
  // Phase C: 하나 완료될 때마다 즉시 브로드캐스트 (채워지는 것 실시간 체감)
  // ---
  console.log('[SYNC] [4.6단계]  신선도 기반 즉시 표시 시작!');
  
  // ════════════════════════════════════════════════════════════════
  // [Phase A] 캐시 파일 복원 + 신선도 분석
  // ════════════════════════════════════════════════════════════════
  const multiTfRestored = loadMultiTfCandleStore();
  
  if (multiTfRestored) {
    console.log('[FAST]  캐시 파일 복원 성공! 신선도 분석 시작...');
    
    // 모든 타임프레임에 대해 신선도 분석
    const TIMEFRAMES_TO_CHECK = [1, 3, 5, 15, 30, 60, 240];
    const EXCHANGES_TO_CHECK = [
      { name: 'binance_spot', markets: BINANCE_SPOT_MARKETS || [] },
      { name: 'binance_futures', markets: BINANCE_FUTURES_MARKETS || [] },
      { name: 'okx_spot', markets: OKX_SPOT_MARKETS || [] },
      { name: 'okx_futures', markets: OKX_FUTURES_MARKETS || [] },
      { name: 'upbit', markets: UPBIT_MARKETS || [] },
      { name: 'bithumb', markets: BITHUMB_MARKETS || [] }
    ];
    
    let totalFresh = 0;
    let totalStale = 0;
    let totalMissing = 0;
    
    // 타임프레임별 신선도 통계
    for (const tf of TIMEFRAMES_TO_CHECK) {
      let tfFresh = 0, tfStale = 0, tfMissing = 0;
      
      for (const exchange of EXCHANGES_TO_CHECK) {
        if (exchange.markets.length === 0) continue;
        
        const analysis = CandleManager.analyzeCacheFreshness(exchange.name, exchange.markets, tf);
        tfFresh += analysis.fresh.length;
        tfStale += analysis.stale.length;
        tfMissing += analysis.missing.length;
      }
      
      totalFresh += tfFresh;
      totalStale += tfStale;
      totalMissing += tfMissing;
      
      if (tfFresh > 0) {
        console.log('   [' + tf + '분봉] 신선: ' + tfFresh + '개, 노후: ' + tfStale + '개, 없음: ' + tfMissing + '개');
      }
    }
    
    console.log('[STAT]  전체 신선도: 신선=' + totalFresh + ', 노후=' + totalStale + ', 없음=' + totalMissing);
    
    // ════════════════════════════════════════════════════════════════
    // [Phase A-2] 신선한 데이터 즉시 브로드캐스트!
    // ════════════════════════════════════════════════════════════════
    if (totalFresh > 0) {
      try {
        console.log('[FAST]  신선한 캐시 ' + totalFresh + '개 즉시 브로드캐스트!');
        updateGlobalMomentumCaches();
        applyGlobalMomentumToCoinData();
        broadcastCoinData('R');
        console.log('[OK]  Phase A 완료! (0초 내 첫 화면 표시!)');
      } catch (cacheErr) {
        console.error('[WARN]  Phase A 브로드캐스트 실패:', cacheErr.message);
      }
    }
  } else {
    console.log('[WARN]  캐시 파일 없음 - 전체 백필 필요');
  }
  
  // ════════════════════════════════════════════════════════════════
  // [Phase B] 우선순위 기반 증분 수집 (백그라운드, 논-블로킹!)
  // - 적게 필요한 것부터 수집 → 빠르게 채워지는 효과
  // - 하나 완료될 때마다 즉시 브로드캐스트
  // ════════════════════════════════════════════════════════════════
  smartPriorityBackfill().then(result => {
    console.log('[OK]  Phase B 완료! (우선순위 백필)');
    console.log('   [STAT] 총 처리: ' + result.total + '개, 신선 유지: ' + result.fresh + '개, 증분 수집: ' + result.backfilled + '개');
  }).catch(err => {
    console.error('[ERROR]  Phase B 오류:', err.message);
  });
  
  // ---
  //  5단계: API 초기화 (논-블로킹! await 제거!)
  // ════════════════════════════════════════════════════════════════
  // 기존: await로 13~25초 블로킹 → 서버 멈춤!
  // 개선: .then()으로 백그라운드 실행 → 서버 즉시 응답 가능!
  // ---
  console.log('[SYNC] [5단계]  API 초기화 (백그라운드)...');
  
  // 5-1. 업비트 24시간 전 가격 조회 (백그라운드)
  fetchUpbit24hPrices().then(() => {
    console.log('   [OK] 5-1. 업비트 24시간 전 가격 조회 완료!');
  }).catch(err => {
    console.error('   [ERROR] 5-1. 업비트 24시간 전 가격 조회 실패:', err.message);
  });
  
  // 5-2. 업비트 캔들 캐시 갱신 (백그라운드)
  updateUpbitCandleCache().then(() => {
    console.log('   [OK] 5-2. 업비트 캔들 캐시 갱신 완료!');
    // 업비트 캔들 갱신 후 모멘텀 재계산 + 브로드캐스트
    updateGlobalMomentumCaches();
    applyGlobalMomentumToCoinData();
    broadcastCoinData('R');
  }).catch(err => {
    console.error('   [ERROR] 5-2. 업비트 캔들 캐시 갱신 실패:', err.message);
  });
  
  // 5-3. 전체 모멘텀 갱신 (백그라운드)
  updateAllMomentums().then(() => {
    console.log('   [OK] 5-3. 전체 모멘텀 갱신 완료!');
    //  브로드캐스트 전 캐시 동기화 (글로벌/국내 모두)
    updateGlobalMomentumCaches();
    applyGlobalMomentumToCoinData();
    broadcastCoinData('R');
  }).catch(err => {
    console.error('   [ERROR] 5-3. 전체 모멘텀 갱신 실패:', err.message);
  });
  
  // 5-4. 빗썸 5분봉 캐시 갱신 (백그라운드)
  console.log('   [DATA] 5-4. 빗썸 5분봉 캐시 갱신 (백그라운드)...');
  updateBithumb5MinCache();
  
  // 5-5. 빗썸 1시간봉 캐시 갱신 (백그라운드)
  console.log('   [DATA] 5-5. 빗썸 1시간봉 캐시 갱신 (백그라운드)...');
  updateBithumb1HourCache();
  
  console.log('[OK] [5단계] API 초기화 시작됨! (백그라운드 논-블로킹)');
  console.log('[FAST]  서버 즉시 응답 가능! (await 블로킹 0초!)');
  
  // ---
  // 6단계: 정기 갱신 스케줄 시작 (초기화 완료 후!)
  //  Round-Robin 시스템으로 전환
  // ---
  console.log('[TIME] [6단계] 정기 갱신 스케줄 시작...');
  
  //  Zero-Polling: 주기적 API 호출 제거!
  // - 초기 1회 호출 후, WebSocket 틱으로만 캔들 유지
  // - 아래 setInterval들은 더 이상 사용하지 않음
  
  // setInterval(fetchUpbit24hPrices, 600000);    //  제거: 24시간 가격은 초기 1회만
  // setInterval(updateBithumb5MinCache, 300000); //  제거: 빗썸도 WebSocket 틱 사용
  // setInterval(updateUpbitCandleCache, 300000); //  제거: 캔들은 틱으로 합성

  //  기존 방식 삭제:
  // - setInterval(updateAllMomentums, 300000);  ← 삭제됨 (현재 선택된 분봉만 갱신하던 방식)
  // - setInterval(preloadAllTimeframes, 600000); ← 삭제됨 (Lazy Loading 방식)

  //  Round-Robin 순환 갱신 시스템 시작!
  // - 5분마다 모든 타임프레임을 순환하며 갱신
  // - 사용자가 클릭하지 않아도 모든 시간대 데이터가 최신화됨
  startRoundRobinUpdate();
  
  // ---
  //  동시접속자 통계 시스템 (확장판)
  // - 피크 기록 파일 저장/복원
  // - 시간대별 평균 (오전/오후/저녁/심야)
  // - 일별/주별 통계 JSON 저장
  // - 50명+ 알림 로그
  // ---
  
  // 통계 파일 로드 (서버 재시작 시 피크 기록 복원)
  UserStatsManager.loadFromFile();
  
  // 3분마다 통계 수집 및 로깅
  setInterval(() => {
    const currentUsers = clients.size;
    
    // 타임프레임별 구독자 수 집계
    const tfStats = {};
    clients.forEach(ws => {
      const tf = ws.clientTimeframe || 'unknown';
      tfStats[tf] = (tfStats[tf] || 0) + 1;
    });
    
    // UserStatsManager에 샘플 기록
    const result = UserStatsManager.recordSample(currentUsers, tfStats);
    
    // 기본 로그 출력
    console.log('[USERS] ' + result.timestamp + 
      ' | 현재: ' + result.currentUsers + 
      ' | 오늘피크: ' + result.todayPeak + 
      ' | 역대피크: ' + result.allTimePeak + 
      ' | ' + result.periodName +
      ' | TF: ' + JSON.stringify(tfStats));
    
    // 알림 로그 출력 (피크 갱신, 50명+ 등)
    for (const alert of result.alerts) {
      console.log('[USERS] ' + alert);
    }
  }, 3 * 60 * 1000);  // 3분
  
  // 10분마다 통계 파일 저장 (캔들 저장과 동시에)
  setInterval(() => {
    UserStatsManager.saveToFile();
  }, 10 * 60 * 1000);  // 10분
  
  // 1시간마다 시간대별 평균 로그 출력
  setInterval(() => {
    const avgs = UserStatsManager.getTimePeriodAverages();
    console.log('[USERS] [시간대별 평균] ' +
      '오전: ' + avgs.morning + ' | ' +
      '오후: ' + avgs.afternoon + ' | ' +
      '저녁: ' + avgs.evening + ' | ' +
      '심야: ' + avgs.night);
  }, 60 * 60 * 1000);  // 1시간
  
  // 자정에 일별 요약 로그 출력 (매일 00:00~00:05 사이에 체크)
  setInterval(() => {
    const now = new Date();
    const kstNow = new Date(now.toLocaleString('en-US', { timeZone: 'Asia/Seoul' }));
    const hour = kstNow.getHours();
    const minute = kstNow.getMinutes();
    
    // 자정 직후 (00:00~00:05)에만 실행
    if (hour === 0 && minute < 5) {
      // 어제 날짜 계산
      const yesterday = new Date(kstNow);
      yesterday.setDate(yesterday.getDate() - 1);
      const yesterdayStr = yesterday.toISOString().split('T')[0];
      
      const summary = UserStatsManager.getDailySummary(yesterdayStr);
      if (summary) {
        console.log('[USERS] [일별 요약] ' + summary.date + 
          ' | 평균: ' + summary.average + '명' +
          ' | 피크: ' + summary.peak + '명' +
          ' | 샘플: ' + summary.sampleCount + '회');
      }
      
      // 월요일이면 주간 요약도 출력
      if (kstNow.getDay() === 1) {
        const lastWeek = new Date(kstNow);
        lastWeek.setDate(lastWeek.getDate() - 7);
        const weekStr = UserStatsManager.getWeekNumber(lastWeek);
        const weeklySummary = UserStatsManager.getWeeklySummary(weekStr);
        if (weeklySummary) {
          console.log('[USERS] [주간 요약] ' + weeklySummary.week +
            ' | 평균: ' + weeklySummary.average + '명' +
            ' | 피크: ' + weeklySummary.peak + '명' +
            ' | 샘플: ' + weeklySummary.sampleCount + '회');
        }
      }
    }
  }, 5 * 60 * 1000);  // 5분마다 체크
  
  console.log('[USERS]  동시접속자 통계 시스템 시작');
  console.log('   [3분] 샘플 수집, [10분] 파일 저장, [1시간] 시간대별 평균, [자정] 일별/주별 요약');

  // ---
  // 6.5단계:  글로벌 캔들 주기적 저장 (10분마다)
  // - 서버 종료/재시작 시 데이터 손실 방지
  // ---
  setInterval(() => {
    saveGlobalCandleStoreToFile();
    saveMultiTfCandleStore();  //  Multi-TF 캔들도 저장
    save1HourCacheToFile();    //  빗썸 1시간봉 캐시도 저장
  }, 10 * 60 * 1000);  // 10분
  
  // ---
  // 6.55단계:  업비트/빗썸 Multi-TF 캔들 증분 갱신 (30분마다)
  // - 타임프레임별 캔들을 최신 상태로 유지
  // ---
  setInterval(updateMultiTfCandlesIncremental, 30 * 60 * 1000);  // 30분
  console.log('[SYNC]  Multi-TF 증분 갱신 스케줄 시작 (30분 주기)');
  
  // ---
  //  빗썸 1시간봉 캐시 주기적 갱신 (30분마다)
  // - 4시간봉 합성에 필요한 1시간봉 데이터 최신화
  // ---
  setInterval(updateBithumb1HourCache, 30 * 60 * 1000);  // 30분
  console.log('[SYNC]  빗썸 1시간봉 캐시 갱신 스케줄 시작 (30분 주기)');
  
  // ---
  // 6.6단계:  MultiTfArchiver 및 HistoricalBackfiller 초기화
  // - 기존 아카이브 데이터 로드
  // - 주기적 flush 스케줄러 시작
  // - 백그라운드 과거 데이터 수집 시작
  // ---
  console.log('[SAVE] [6.6단계] MultiTfArchiver 초기화 시작...');
  MultiTfArchiver.loadExistingData();
  
  console.log('[SAVE] [6.6단계] MultiTfArchiver 주기적 flush 스케줄러 시작...');
  setInterval(() => {
    MultiTfArchiver.flush();
  }, ARCHIVE_FLUSH_INTERVAL);  // 1분마다
  
  // 1시간마다 파일 한도 트림 (40,000개 초과 시)
  setInterval(() => {
    MultiTfArchiver.trimFiles();
  }, 60 * 60 * 1000);  // 1시간마다
  
  // HistoricalBackfiller 초기화
  console.log('[IN] [6.6단계] HistoricalBackfiller 초기화...');
  HistoricalBackfiller.init();
  
  // 마켓 코드 로드 완료 후 pending symbols 설정
  setTimeout(() => {
    console.log('[IN] [6.6단계] HistoricalBackfiller 수집 대상 설정...');
    if (typeof UPBIT_MARKETS !== 'undefined' && UPBIT_MARKETS.length > 0) {
      HistoricalBackfiller.setPendingSymbols('upbit', UPBIT_MARKETS);
    }
    if (typeof BITHUMB_MARKETS !== 'undefined' && BITHUMB_MARKETS.length > 0) {
      HistoricalBackfiller.setPendingSymbols('bithumb', BITHUMB_MARKETS);
    }
    if (typeof BINANCE_SPOT_MARKETS !== 'undefined' && BINANCE_SPOT_MARKETS.length > 0) {
      HistoricalBackfiller.setPendingSymbols('binance_spot', BINANCE_SPOT_MARKETS);
    }
    if (typeof BINANCE_FUTURES_MARKETS !== 'undefined' && BINANCE_FUTURES_MARKETS.length > 0) {
      HistoricalBackfiller.setPendingSymbols('binance_futures', BINANCE_FUTURES_MARKETS);
    }
    if (typeof OKX_SPOT_MARKETS !== 'undefined' && OKX_SPOT_MARKETS.length > 0) {
      HistoricalBackfiller.setPendingSymbols('okx_spot', OKX_SPOT_MARKETS);
    }
    if (typeof OKX_FUTURES_MARKETS !== 'undefined' && OKX_FUTURES_MARKETS.length > 0) {
      HistoricalBackfiller.setPendingSymbols('okx_futures', OKX_FUTURES_MARKETS);
    }
    console.log('[IN] [6.6단계] HistoricalBackfiller 수집 대상 설정 완료');
    console.log('   └─ 상태:', JSON.stringify(HistoricalBackfiller.getStatus().exchanges, null, 2).substring(0, 200) + '...');
  }, 30000);  // 마켓 코드 로드 대기 (30초)
  
  // 백그라운드 과거 데이터 수집 스케줄러 (5분마다)
  console.log('[IN] [6.6단계] HistoricalBackfiller 백그라운드 스케줄러 시작 (5분 간격)...');
  setInterval(() => {
    HistoricalBackfiller.runBackfill();
  }, HistoricalBackfiller.BACKFILL_INTERVAL);
  
  // 첫 수집은 1분 후 시작 (서버 안정화 대기)
  setTimeout(() => {
    console.log('[IN] [BACKFILL] 첫 번째 과거 데이터 수집 시작...');
    HistoricalBackfiller.runBackfill();
  }, 60000);
  
  // 서버 종료 시 강제 flush (graceful shutdown)
  process.on('SIGTERM', async () => {
    console.log('[SHUTDOWN] SIGTERM 수신 - 서버 종료 시작...');
    await MultiTfArchiver.forceFlush();
    process.exit(0);
  });
  
  process.on('SIGINT', async () => {
    console.log('[SHUTDOWN] SIGINT 수신 - 서버 종료 시작...');
    await MultiTfArchiver.forceFlush();
    process.exit(0);
  });
  
  // ---
  // 7단계: 모든 타임프레임 강제 초기화 (Eager Loading)
  //  서버 시작 시 모든 분봉 데이터 즉시 계산
  // ---
  console.log('[START] [7단계] 모든 타임프레임 강제 초기화 시작...');
  initializeAllTimeframes();
  
  console.log('[OK] 서버 초기화 완료! 클라이언트 접속 대기 중...');
});

// ---
//  모든 타임프레임 강제 초기화 (Eager Loading)
// - 서버 시작 시 모든 타임프레임을 강제로 계산
// - "이미 캐시가 있으면 스킵" 로직 제거!
// ---
async function initializeAllTimeframes() {
  if (!marketsLoaded) {
    console.log('⏳ 타임프레임 초기화 대기 중... (마켓 로딩 필요)');
    return;
  }
  
  console.log('[START] [Eager Loading] 모든 타임프레임 강제 초기화 시작...');
  console.log('[DATA] 대상 타임프레임: ' + ALLOWED_TIMEFRAMES.join(', ') + '분');
  
  for (const tf of ALLOWED_TIMEFRAMES) {
    console.log('[DATA] [초기화] 타임프레임 ' + tf + '분 계산 중...');
    await updateMomentumForTimeframe(tf);
    
    // 타임프레임 간 대기 (스케줄러가 개별 요청 간격 관리, 여기선 그룹 간 대기만)
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  
  console.log('[OK] [Eager Loading] 모든 타임프레임 강제 초기화 완료!');
}

// ---
//  Round-Robin 순환 갱신 시스템
// - 모든 타임프레임을 5분(300000ms)마다 순환하며 갱신
// - 사용자가 클릭하지 않아도 모든 시간대 데이터가 최신화됨
// ---
let roundRobinIndex = 0;  // 현재 갱신 중인 타임프레임 인덱스
let roundRobinRunning = false;  // 중복 실행 방지

async function roundRobinUpdate() {
  if (!marketsLoaded) {
    console.log('⏳ [Round-Robin] 마켓 로딩 대기 중...');
    return;
  }
  
  if (roundRobinRunning) {
    console.log('⏭️ [Round-Robin] 이전 갱신 진행 중, 스킵...');
    return;
  }
  
  roundRobinRunning = true;
  
  try {
    // 현재 타임프레임
    const tf = ALLOWED_TIMEFRAMES[roundRobinIndex];
    console.log('[SYNC] [Round-Robin] 타임프레임 ' + tf + '분 갱신 시작... (인덱스: ' + roundRobinIndex + '/' + ALLOWED_TIMEFRAMES.length + ')');
    
    await updateMomentumForTimeframe(tf);
    
    // 다음 타임프레임으로 인덱스 이동 (순환)
    roundRobinIndex = (roundRobinIndex + 1) % ALLOWED_TIMEFRAMES.length;
    
    console.log('[OK] [Round-Robin] 타임프레임 ' + tf + '분 갱신 완료! (다음: ' + ALLOWED_TIMEFRAMES[roundRobinIndex] + '분)');
  } catch (error) {
    console.error('[ERROR] [Round-Robin] 갱신 오류:', error.message);
  } finally {
    roundRobinRunning = false;
  }
}

// Round-Robin 갱신 시스템 시작 함수
function startRoundRobinUpdate() {
  console.log('[SYNC] [Round-Robin] 순환 갱신 시스템 시작!');
  console.log('   - 갱신 주기: 3초');
  console.log('   - 대상 타임프레임: ' + ALLOWED_TIMEFRAMES.join(', ') + '분');
  console.log('   - 전체 순환 주기: ' + (ALLOWED_TIMEFRAMES.length * 3) + '초');
  
  // ---
  //  Pre-calculation 활성화!
  // - 기존 server57: Zero-Polling으로 setInterval 비활성화
  // - 변경: 3초마다 모든 타임프레임 순환하며 미리 계산
  // - 목적: 사용자 클릭 시 Zero Latency로 결과 표시
  // ---
  setInterval(roundRobinUpdate, 3000);  // 3초마다 다음 타임프레임 갱신
  console.log('[OK]  Pre-calculation 모드: 3초마다 Round-Robin 갱신 활성화됨');
}
