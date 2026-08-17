/* fixture app — React 18 스타일 + 미매칭 난독화 자산 포함 */
(function () {
  "use strict";
  const React = { version: "18.2.0" };
  function createRoot(container) {
    return { render: function (el) { container.appendChild(el); } };
  }
  const useId = "hid";
  createRoot(document.getElementById("root")).render(
    document.createElement("div")
  );
  /* 난독화된 미지의 프레임워크 흔적 — 결정론 시그니처로 못 잡는 자산 */
  var _0xabc = ["SomeFramework"]; window.__unk = _0xabc;
})();
