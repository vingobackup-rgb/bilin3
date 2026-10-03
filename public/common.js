export const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function formData(form) { return Object.fromEntries(new FormData(form)); }
export function field(label,name,value='',options={}) {
  const {type='text',required=false,autocomplete='',max=200,placeholder='',wide=false}=options;
  return `<label class="field ${wide?'wide':''}"><span>${label}</span><input name="${name}" type="${type}" value="${esc(value)}" ${required?'required':''} maxlength="${max}" ${type==='password'?'minlength="10"':''} autocomplete="${autocomplete}" placeholder="${esc(placeholder)}"></label>`;
}
export const area=(label,name,value='',max=2000)=>`<label class="field wide"><span>${label}</span><textarea name="${name}" maxlength="${max}" rows="3">${esc(value)}</textarea></label>`;
export const date=value=>value?new Date(value).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false}):'—';
export function apiClient(getCsrf) {
  return async (path,method='GET',body) => {
    const res=await fetch(path,{method,headers:{'Content-Type':'application/json',...(getCsrf()?{'X-CSRF-Token':getCsrf()}: {})},credentials:'same-origin',body:body===undefined?undefined:JSON.stringify(body)});
    const data=await res.json();if(!res.ok)throw Object.assign(new Error(data.error||'操作失败'),{status:res.status});return data;
  };
}
let toastTimer;
export function toast(message) { const node=document.querySelector('#toast');node.textContent=message;node.classList.add('visible');clearTimeout(toastTimer);toastTimer=setTimeout(()=>node.classList.remove('visible'),4500); }
export function modal(html) { document.querySelector('#dialog-content').innerHTML=html;document.querySelector('#dialog').showModal(); }
export function closeModal(){document.querySelector('#dialog').close();}
document.querySelector('.dialog-close').addEventListener('click',closeModal);
export async function submit(form,task) {
  const button=form.querySelector('[type="submit"]');if(button.disabled)return;
  const label=button.textContent;button.disabled=true;button.textContent='正在处理…';
  form.querySelector('.form-error')?.remove();
  try{await task();}catch(error){const p=document.createElement('p');p.className='form-error';p.setAttribute('role','alert');p.textContent=error.message;form.append(p);}
  finally{button.disabled=false;button.textContent=label;}
}
export function addressFields(a={}) {
  return `${field('地址标签','label',a.label,{max:40,placeholder:'家 / 公司'})}${field('收件人','recipient',a.recipient,{required:true,max:100,autocomplete:'name'})}${field('收件电话','phone',a.phone,{required:true,max:40,type:'tel',autocomplete:'tel'})}${field('收件邮箱（选填）','email',a.email,{type:'email',autocomplete:'email'})}${field('国家 / 地区','country',a.country,{required:true,max:80,autocomplete:'country-name'})}${field('省 / 州（选填）','province',a.province,{max:100,autocomplete:'address-level1'})}${field('城市','city',a.city,{required:true,max:100,autocomplete:'address-level2'})}${field('邮编（选填）','postcode',a.postcode,{max:30,autocomplete:'postal-code'})}${field('街道与门牌','street',a.street,{required:true,max:500,wide:true,autocomplete:'address-line1'})}${field('补充地址（选填）','extra',a.extra,{max:300,wide:true,autocomplete:'address-line2'})}<label class="check wide"><input type="checkbox" name="is_default" ${a.is_default?'checked':''}>设为默认地址</label>`;
}
export const warehouseHtml=w=>`<dl class="warehouse"><div><dt>收件人</dt><dd>${esc(w.recipient)}</dd></div><div><dt>联系电话</dt><dd>${esc(w.phone)}</dd></div><div><dt>收货地址</dt><dd>${esc(w.address)}</dd></div></dl>`;
export async function copy(value){try{await navigator.clipboard.writeText(value);toast('已复制');}catch{modal(`<h2>复制收货信息</h2><p class="muted">长按或选中下方文字复制。</p><textarea class="copy-text" readonly>${esc(value)}</textarea>`);}}
