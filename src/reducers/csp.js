/**
 * CSP reducer
 * Stores the nonce for server-side rendering
 */

const initialState = {
  nonce: null,
};

export default function csp(state = initialState, action = {}) {
  switch (action.type) {
    case 'SET_CSP_NONCE':
      return {
        ...state,
        nonce: action.nonce,
      };
    default:
      return state;
  }
}
